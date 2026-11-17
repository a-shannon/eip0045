// SPDX-License-Identifier: MIT
package sigma.stark.profile

import java.nio.charset.StandardCharsets
import java.nio.file.{Files, Path, Paths}

/** Verify one raw succinct seal against the expected application payload. */
object Lift15Demo {
  private val profileId = hex("5649af920f3119ca06e8566d836d3c89de81af52ef3d140a0ad7012ca364d35c")
  private val chainDomain = hex("b0244dfc267baca974a4caee06120321562784303a8a688976ae56170e4d175b")

  private def hex(value: String): Array[Byte] = {
    require(value.matches("(?:[0-9a-fA-F]{2})+"), "expected hexadecimal bytes")
    value.grouped(2).map(Integer.parseInt(_, 16).toByte).toArray
  }

  private def read(path: Path, maximum: Int): Array[Byte] = {
    val in = Files.newInputStream(path)
    try {
      val bytes = in.readNBytes(maximum + 1)
      require(bytes.length <= maximum, s"input exceeds $maximum bytes")
      bytes
    } finally in.close()
  }

  private def run(args: Array[String]): Int = {
    require(args.length == 4, "usage: Lift15Demo PROFILE_DIR RAW_SEAL PROGRAM_ID_HEX PAYLOAD")
    val dir = Paths.get(args(0))
    val loaded = Risc0ProfilePackageLoader.load(
      read(dir.resolve("manifest.bin"), Risc0ProfilePackageLoader.ManifestBytes),
      read(dir.resolve("algorithm.txt"), Risc0ProfilePackageLoader.MaxAlgorithmBytes),
      read(dir.resolve("constants.bin"), Risc0ProfilePackageLoader.BinaryDataBytes),
      profileId).fold(err => throw new IllegalArgumentException(s"profile: $err"), identity)
    val program = hex(args(2))
    require(program.length == 32, "program ID must contain 32 bytes")
    val proposition = hex("1c53020e20") ++ program ++ hex("0e20") ++ profileId ++
      hex("d1b9e4e3001ae4e3010e73007301")
    val payload = args(3).getBytes(StandardCharsets.UTF_8)
    val binding = Risc0ClaimBuilder.build(loaded, chainDomain, program,
      ProfileBlake2b256.hash(proposition), payload)
      .fold(err => throw new IllegalArgumentException(s"statement: $err"), identity)
    val bytes = read(Paths.get(args(1)), loaded.exactProofBytes)
    val chunks = bytes.grouped(65535).toArray
    loaded.verifier.verify(chunks, binding.expectedClaim) match {
      case Right(Risc0RawSealVerifier.Verified(1, 15)) =>
        println("ACCEPT lift-po2-15")
        0
      case Right(_) =>
        println("REJECT unexpected-terminal")
        1
      case Left(failure) =>
        println(s"REJECT ${failure.code}")
        1
    }
  }

  def main(args: Array[String]): Unit = {
    val status = try run(args) catch {
      case e: IllegalArgumentException =>
        System.err.println(e.getMessage)
        2
      case e: java.io.IOException =>
        System.err.println(e.getMessage)
        2
    }
    sys.exit(status)
  }
}
