// SPDX-License-Identifier: MIT
package sigma.stark.profile

import java.nio.charset.StandardCharsets
import java.nio.file.{Files, Path, Paths}
import java.security.MessageDigest

/** Driver for the unmodified 3.1.0 demo verifier. Case ancestry is checked by the producer replay. */
object Recursive310 {
  private def hex(value: String): Array[Byte] =
    value.grouped(2).map(Integer.parseInt(_, 16).toByte).toArray
  private def show(value: Array[Byte]): String = value.map(x => f"${x & 255}%02x").mkString
  private def sha(value: Array[Byte]): String = show(MessageDigest.getInstance("SHA-256").digest(value))
  private def read(path: Path, max: Int): Array[Byte] = {
    val stream = Files.newInputStream(path)
    try {
      val bytes = stream.readNBytes(max + 1)
      require(bytes.length <= max, s"oversize: $path")
      bytes
    } finally stream.close()
  }

  def main(args: Array[String]): Unit = {
    require(args.length == 4, "expected CASE PROFILE_DIR RAW_SEAL SHA256")
    val expected = args(0) match {
      case "8" | "10" => Risc0RawSealVerifier.Verified(2, 0)
      case "9" => Risc0RawSealVerifier.Verified(3, 0)
      case _ => throw new IllegalArgumentException("expected case 8, 9, or 10")
    }
    val dir = Paths.get(args(1))
    val seal = Paths.get(args(2))
    val profileId = hex("5649af920f3119ca06e8566d836d3c89de81af52ef3d140a0ad7012ca364d35c")
    val domain = hex("b0244dfc267baca974a4caee06120321562784303a8a688976ae56170e4d175b")
    val image = hex("b574db28719df2261c18b5c5f0a52ad5ad96a290679df3223c1c3acacd0fca9c")
    val prop = hex("1c53020e20") ++ image ++ hex("0e20") ++ profileId ++
      hex("d1b9e4e3001ae4e3010e73007301")
    val loaded = Risc0ProfilePackageLoader.load(
      read(dir.resolve("manifest.bin"), Risc0ProfilePackageLoader.ManifestBytes),
      read(dir.resolve("algorithm.txt"), Risc0ProfilePackageLoader.MaxAlgorithmBytes),
      read(dir.resolve("constants.bin"), Risc0ProfilePackageLoader.BinaryDataBytes),
      profileId).fold(e => throw new IllegalArgumentException(e.toString), identity)
    val original = "Ergo EIP-0045 local demo v3.1.0".getBytes(StandardCharsets.UTF_8)
    val mutated = original.clone()
    mutated(mutated.length - 1) = (mutated.last ^ 1).toByte
    val primary = read(seal, loaded.exactProofBytes)
    require(primary.length == loaded.exactProofBytes && sha(primary) == args(3), "seal identity mismatch")
    def verify(payload: Array[Byte], expectedStatement: String) = {
      val binding = Risc0ClaimBuilder.build(loaded, domain, image, ProfileBlake2b256.hash(prop), payload)
        .fold(e => throw new IllegalArgumentException(e.toString), identity)
      require(sha(binding.statement) == expectedStatement, "statement identity mismatch")
      loaded.verifier.verify(primary.grouped(65535).toArray, binding.expectedClaim)
    }
    val originalHash = "e8eb87bdd03c109a13f549e64ab5cd6597b890c024a3c39830726dc814676715"
    val first = verify(original, originalHash)
    require(first == Right(expected), s"wrong original verdict for case ${args(0)}: $first")
    val secondBinding = Risc0ClaimBuilder.build(loaded, domain, image, ProfileBlake2b256.hash(prop), mutated)
      .fold(e => throw new IllegalArgumentException(e.toString), identity)
    require(sha(secondBinding.statement) == "3f16e6af09e001feb58611acd32d09d988258846cd260c2787a114af893a4287",
      "changed statement differs from expected one-bit mutation")
    val second = loaded.verifier.verify(primary.grouped(65535).toArray, secondBinding.expectedClaim)
    require(second.left.toOption.exists(_.code == "raw-seal-claim-mismatch"), s"wrong mutated verdict: $second")
    require(sha(primary) == args(3) && sha(read(seal, loaded.exactProofBytes)) == args(3), "seal changed")
    println(s"case=${args(0)} sealSha256=${args(3)} bytes=${primary.length} kind=${expected.controlKind} parameter=${expected.controlParameter}")
    println(s"JVM: ACCEPT case ${args(0)}")
    println("JVM: REJECT raw-seal-claim-mismatch")
  }
}
