package iohk

import org.scalacheck.Arbitrary.arbBigInt
import org.scalacheck.Prop.BooleanOperators
import org.scalatest.prop.Checkers
import org.scalatest.{Matchers, WordSpec}

class DJTest extends WordSpec with Matchers with Checkers {

  val djA = new DJ{}
  val djB = new DJ{ val pubK = publicKey}

  "encrypt/decrypt" should {
    "retore the original value" in {
      check { (sBG: BigInt) =>
        (sBG > 0 ) ==> {
          val secret = sBG.bigInteger
          val result = djB.decryptBigInt(djA.encryptBigInt(djB.pubK)(secret))
          result == secret
        }
      }
    }
  }

}
