package iohk

import java.math.BigInteger
import java.security.SecureRandom

import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.damgardJurikProduct.{SigmaDJProductProverComputation, SigmaDJProductProverInput, SigmaDJProductVerifierComputation}
import edu.biu.scapi.interactiveMidProtocols.zeroKnowledge.{ZKFromSigmaProver, ZKFromSigmaVerifier}
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.{DamgardJurikPrivateKey, DamgardJurikPublicKey}
import edu.biu.scapi.midLayer.ciphertext.{AsymmetricCiphertext, BigIntegerCiphertext}
import edu.biu.scapi.midLayer.plaintext.BigIntegerPlainText
import org.scalacheck.Arbitrary.arbBigInt
import org.scalacheck.Prop.BooleanOperators
import cats.implicits._
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.damgardJurikKnowledge.SigmaDJKnowledgeCommonInput
import org.scalatest._
import Matchers._
import java.util.concurrent._
import scala.concurrent.duration._
import org.scalatest.concurrent.Futures
import org.scalatest.prop.Checkers
import org.scalatest.{Matchers, WordSpec}

import scala.concurrent.{Await, Future}

class DJProvVerifTest extends WordSpec with Matchers with Checkers with Futures {

  val dj = new DJ{ val pubK = publicKey; val privK = privateKey}

  def toBGCt( as: AsymmetricCiphertext) = as.asInstanceOf[BigIntegerCiphertext]
  def toBIPT(x: BigInteger) = new BigIntegerPlainText(x)
  def encrypt(x: BigInteger) = dj.encryptBigInt(dj.pubK)(x)



  "DJ Prover Verifier" should {
    "prove and verify" in {



      val a = 5
      val b = 2
      val c = a*b

      val bigIntValues = List(a,b,c).map(x => BigInt(x).bigInteger)

      val List(cA,cB, cC) = bigIntValues.map(encrypt)
      val List(txtA, txtB, txtC) = bigIntValues.map(toBIPT)


      val channel = new QueueChannel
      val sVC = new SigmaDJProductVerifierComputation()


      val sigma = new SigmaDJProductProverComputation()
      val prover = new ZKFromSigmaProver(channel, sigma)

      val pInput = new SigmaDJProductProverInput(dj.pubK.asInstanceOf[DamgardJurikPublicKey],
        toBGCt(cA), toBGCt(cB), toBGCt(cC), dj.privK.asInstanceOf[DamgardJurikPrivateKey], txtA, txtB )

      val vInput = pInput.getCommonParams //new SigmaDJKnowledgeCommonInput(dj.pubK.asInstanceOf[DamgardJurikPublicKey], cA.asInstanceOf[BigIntegerCiphertext])

      val validator = new ZKFromSigmaVerifier(channel, sVC, new SecureRandom)

      import scala.concurrent.ExecutionContext.Implicits.global

      val r = for {
        fv <- Future {
          validator.verify(vInput)
        }
        fp <- Future {
          prover.prove(pInput)
        }
      } yield (fv)

      val x= Await.result(r, 10.seconds)
        println( s"x = $x " )

    }
  }


}
