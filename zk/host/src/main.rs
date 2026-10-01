// abd-zk-host: proves and verifies relation R (zk/methods/guest) with RISC Zero.
//
//   abd-zk-host image-id                          -> {"image_id": ...}
//   abd-zk-host execute WITNESS.json              -> {"journal_hex": ..., cycles, segments} (no proof)
//   abd-zk-host prove WITNESS.json RECEIPT.bin     -> proving statistics (JSON)
//   abd-zk-host verify RECEIPT.bin IMAGE_ID        -> {"verified": ..., "journal_hex": ...}
//   abd-zk-host soundness                         -> the vendor calculator's security levels (bits)
//
// Verification accepts only a single-segment succinct receipt whose segment is at most 2^MAX_ACCEPTED_PO2
// cycles.  End-to-end soundness is bounded by the weaker of the RISC-V segment proof and the recursion
// proof; bounding the accepted segment size keeps a forger from using a larger (weaker) segment.
//
// Only succinct (recursion) receipts are produced or accepted; Groth16 receipts are not
// post-quantum.  A succinct receipt does not hide the execution length: its public control
// id names the last recursion program, i.e. join for two or more segments, or, for one
// segment, the lift program of that segment's padded power-of-two cycle count.
// Proving is local and in-process (LocalProver, whatever RISC0_PROVER says); RISC0_DEV_MODE
// (fake proofs) is refused.

use std::{env, fs, time::Instant};

use hex::FromHex;
use methods::{RELATION_ELF, RELATION_ID};
use risc0_zkvm::{
    sha::Digest, ExecutorEnv, ExecutorImpl, InnerReceipt, LocalProver, NullSegmentRef, Prover, ProverOpts, Receipt,
    ALLOWED_CONTROL_IDS,
};
use serde_json::json;

/// Largest RISC-V segment (as a power of two of cycles) whose lift receipt is accepted.
const MAX_ACCEPTED_PO2: usize = 19;

fn vm_hwm_kib() -> Option<u64> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|l| l.starts_with("VmHWM:"))?;
    line.split_whitespace().nth(1)?.parse().ok()
}

fn image_id() -> String {
    Digest::from(RELATION_ID).to_string()
}

fn segment_po2() -> u32 {
    env::var("ABD_ZK_PO2").ok().and_then(|s| s.parse().ok()).unwrap_or(19)
}

fn executor_env(witness: &str) -> anyhow::Result<ExecutorEnv<'static>> {
    ExecutorEnv::builder().write(&witness.to_string())?.segment_limit_po2(segment_po2()).build()
}

// Recursion program named by a succinct receipt's control id.  Positions follow
// ALLOWED_CONTROL_IDS of risc0-circuit-recursion 4.0.5 (pinned through risc0-zkvm =3.0.6):
// 1 = join, 4..=12 = lift_rv32im_v2_14..22.
fn recursion_program(control_id: &Digest) -> (String, Option<usize>) {
    match ALLOWED_CONTROL_IDS.iter().position(|c| c == control_id) {
        Some(1) => ("join".into(), None),
        Some(i @ 4..=12) => (format!("lift_rv32im_v2_{}", i + 10), Some(i + 10)),
        Some(i) => (format!("allowed_control_id[{i}]"), None),
        None => ("unknown".into(), None),
    }
}

fn execute(witness_path: &str) -> anyhow::Result<()> {
    let witness = fs::read_to_string(witness_path)?;
    let mut po2s = Vec::new();
    let session = ExecutorImpl::from_elf(executor_env(&witness)?, RELATION_ELF)?.run_with_callback(|segment| {
        po2s.push(segment.po2());
        Ok(Box::new(NullSegmentRef))
    })?;
    let stats = session.stats();
    let exit_code = format!("{:?}", session.exit_code);
    let journal = session.journal.map(|j| j.bytes).unwrap_or_default();
    println!(
        "{}",
        json!({
            "image_id": image_id(), "exit_code": exit_code,
            "journal_hex": hex::encode(&journal), "journal_bytes": journal.len(),
            "total_cycles": stats.total_cycles, "user_cycles": stats.user_cycles,
            "segments": stats.segments, "segment_po2s": po2s,
        })
    );
    Ok(())
}

fn prove(witness_path: &str, receipt_path: &str) -> anyhow::Result<()> {
    let witness = fs::read_to_string(witness_path)?;
    let t0 = Instant::now();
    let info = LocalProver::new("local").prove_with_opts(executor_env(&witness)?, RELATION_ELF, &ProverOpts::succinct())?;
    let prove_s = t0.elapsed().as_secs_f64();
    let receipt = info.receipt;
    let InnerReceipt::Succinct(succinct) = &receipt.inner else {
        anyhow::bail!("prover did not return a succinct receipt");
    };
    let (program, lift_po2) = recursion_program(&succinct.control_id);
    let control_id = succinct.control_id.to_string();
    let bytes = bincode::serialize(&receipt)?;
    fs::write(receipt_path, &bytes)?;
    let t1 = Instant::now();
    receipt.verify(RELATION_ID)?;
    let verify_s = t1.elapsed().as_secs_f64();
    println!(
        "{}",
        json!({
            "image_id": image_id(), "receipt_kind": "succinct", "segment_po2": segment_po2(),
            "prove_s": prove_s, "verify_s": verify_s, "receipt_bytes": bytes.len(),
            "journal_bytes": receipt.journal.bytes.len(), "total_cycles": info.stats.total_cycles,
            "user_cycles": info.stats.user_cycles, "segments": info.stats.segments,
            "control_id": control_id, "recursion_program": program, "lift_po2": lift_po2,
            "peak_rss_kib": vm_hwm_kib(),
        })
    );
    Ok(())
}

fn verify(receipt_path: &str, image_hex: &str) -> anyhow::Result<()> {
    let bytes = fs::read(receipt_path)?;
    let receipt: Receipt = bincode::deserialize(&bytes)?;
    let image = Digest::from_hex(image_hex).map_err(|e| anyhow::anyhow!("bad image id: {e:?}"))?;
    // Only a single-segment succinct receipt of at most 2^MAX_ACCEPTED_PO2 cycles is accepted.
    let (succinct, program, lift_po2) = match &receipt.inner {
        InnerReceipt::Succinct(s) => {
            let (program, lift_po2) = recursion_program(&s.control_id);
            (true, program, lift_po2)
        }
        _ => (false, "not succinct".to_string(), None),
    };
    let size_ok = matches!(lift_po2, Some(p) if p <= MAX_ACCEPTED_PO2);
    let t0 = Instant::now();
    let ok = succinct && size_ok && receipt.verify(image).is_ok();
    let verify_s = t0.elapsed().as_secs_f64();
    println!(
        "{}",
        json!({
            "verified": ok, "receipt_kind_succinct": succinct, "recursion_program": program,
            "lift_po2": lift_po2, "max_accepted_po2": MAX_ACCEPTED_PO2, "verify_s": verify_s,
            "journal_hex": hex::encode(&receipt.journal.bytes),
        })
    );
    Ok(())
}

// Security levels from the vendor's own calculator (risc0_zkp::prove::soundness), in bits:
// toy_model = conjectured under the ethSTARK Toy Problem conjecture; conjectured_strict = FRI
// list-decoding conjecture; proven = proven list-decoding regime.
fn soundness() -> anyhow::Result<()> {
    use risc0_zkp::{
        adapter::TapsProvider,
        field::{
            baby_bear::{BabyBear, BabyBearExtElem},
            ExtElem,
        },
        hal::cpu::CpuHal,
        prove::soundness as calc,
    };
    type H = CpuHal<BabyBear>;
    let ext = BabyBearExtElem::EXT_SIZE;
    let levels = |taps: &risc0_zkp::taps::TapSet, po2: usize| {
        let coeffs = (1usize << po2) * ext;
        json!({
            "po2": po2,
            "toy_model": calc::toy_model_security::<H>(taps, coeffs),
            "conjectured_strict": calc::conjectured_strict::<H>(taps, coeffs),
            "proven": calc::proven::<H>(taps, coeffs),
        })
    };
    let rv32im = risc0_circuit_rv32im::CircuitImpl.get_taps();
    let recursion = risc0_circuit_recursion::CircuitImpl.get_taps();
    let segments: Vec<_> = (14..=22).map(|po2| levels(rv32im, po2)).collect();
    println!(
        "{}",
        json!({
            "calculator": "risc0_zkp::prove::soundness", "risc0_zkp": "3.0.5",
            "max_accepted_po2": MAX_ACCEPTED_PO2,
            "rv32im_segment": segments,
            "recursion": levels(recursion, risc0_zkvm::RECURSION_PO2),
        })
    );
    Ok(())
}

fn main() -> anyhow::Result<()> {
    if env::var_os("RISC0_DEV_MODE").is_some() {
        anyhow::bail!("RISC0_DEV_MODE is set: refusing to produce or accept fake proofs");
    }
    let args: Vec<String> = env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("image-id") => println!("{}", json!({ "image_id": image_id() })),
        Some("execute") if args.len() == 3 => execute(&args[2])?,
        Some("prove") if args.len() == 4 => prove(&args[2], &args[3])?,
        Some("verify") if args.len() == 4 => verify(&args[2], &args[3])?,
        Some("soundness") => soundness()?,
        _ => {
            eprintln!(
                "usage: abd-zk-host image-id | execute WITNESS.json | prove WITNESS.json RECEIPT.bin | verify RECEIPT.bin IMAGE_ID | soundness"
            );
            std::process::exit(2);
        }
    }
    Ok(())
}
