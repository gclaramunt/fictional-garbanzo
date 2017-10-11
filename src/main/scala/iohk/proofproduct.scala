package iohk

import java.io
import java.math.BigInteger
import java.security.{PublicKey, SecureRandom}
import java.util.concurrent.ConcurrentLinkedDeque

import akka.actor.{Actor, ActorLogging, ActorRef, ActorSystem, Props}
import akka.pattern.ask
import akka.util.Timeout
import edu.biu.scapi.comm.Channel
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.damgardJurikKnowledge.SigmaDJKnowledgeCommonInput
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.damgardJurikProduct.{SigmaDJProductProverComputation, SigmaDJProductProverInput, SigmaDJProductVerifierComputation}
import edu.biu.scapi.midLayer.asymmetricCrypto.encryption.{DJKeyGenParameterSpec, ScDamgardJurikEnc}
import edu.biu.scapi.midLayer.ciphertext.{AsymmetricCiphertext, BigIntegerCiphertext}
import iohk.ProductProof.system
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.dlog.SigmaDlogProverComputation
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.dlog.SigmaDlogProverInput
import edu.biu.scapi.interactiveMidProtocols.zeroKnowledge.{ZKCommonInput, ZKFromSigmaProver, ZKFromSigmaVerifier, ZKProver}
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.{DamgardJurikPrivateKey, DamgardJurikPublicKey}
import edu.biu.scapi.midLayer.plaintext.BigIntegerPlainText
import edu.biu.scapi.primitives.dlog.DlogGroup
import edu.biu.scapi.primitives.dlog.miracl.MiraclDlogECF2m

import scala.concurrent.duration._
import scala.util.{Random, Try}

object ProductProof extends App {

  val system = ActorSystem()

  val alice = withEnv(system.actorOf(UserActor.props, name = "Alice"))
  val bob = withEnv(system.actorOf(UserActor.props, name = "Bob"))
  val broker = withEnv(system.actorOf(BrokerActor.props(alice, bob), name = "broker"))

  broker ! Start

  def withEnv(a: ActorRef) = system.actorOf(EnvironmentActor.props(a), name = s"env-${a.path.name}")

}

object Start
object Stop
//for simplicity, let's include the public key in the messages, ideally, they'll be exchanged before
case class AskMsg(pk: PublicKey)
case class CipherMsg(pk: PublicKey, n: AsymmetricCiphertext)
case class Announce(as: AsymmetricCiphertext, bs: AsymmetricCiphertext)
case class Challenge(c: Channel, as: AsymmetricCiphertext, bs: AsymmetricCiphertext, cs: AsymmetricCiphertext)

object EnvironmentActor {
  def props(target: ActorRef) = Props(new EnvironmentActor(target))
}

case class EnvironmentActor(target: ActorRef) extends Actor with ActorLogging {

  override def receive = {
    case m =>
      log.info(s" message: $m from $sender to $target ")
      target forward m
  }
}

object BrokerActor {
  def props(alice: ActorRef, bob: ActorRef) = Props(new BrokerActor(alice, bob))
}

case class BrokerActor(alice: ActorRef, bob: ActorRef) extends Actor with DJ with ActorLogging {

  import context.dispatcher

  var fromA, fromB : BigInteger =_

  override def receive = {
    case Start =>
      implicit val timeout = Timeout(10.seconds)
      for {
        cPkA <- alice ? AskMsg(publicKey)
        cPkB <- bob ? AskMsg(publicKey)
      } yield {

        val CipherMsg(pkA, cA) = cPkA
        val CipherMsg(pkB, cB) = cPkB

        val announce = Announce(cA, cB)

        alice ! announce
        bob ! announce

        fromA = decryptBigInt(cA)
        fromB = decryptBigInt(cB)
        val mult = fromA.multiply(fromB)
        val cMultA = encryptBigInt(pkA)(mult)
        val cMultB = encryptBigInt(pkB)(mult)

        log.info(
          s" got fromA = $fromA fromB = $fromB sending mult ${mult.intValue()}")
        alice ! CipherMsg(publicKey, cMultA)
        bob ! CipherMsg(publicKey, cMultB)

      }

    case Challenge(channel, cA, cB, cC) =>

      def toBGCt( as: AsymmetricCiphertext) = as.asInstanceOf[BigIntegerCiphertext]
      val sigma = new SigmaDJProductProverComputation()
      val prover = new ZKFromSigmaProver(channel, sigma)
      val txtA = new BigIntegerPlainText(fromA)
      val txtB = new BigIntegerPlainText(fromB)
      val input = new SigmaDJProductProverInput(publicKey.asInstanceOf[DamgardJurikPublicKey],
        toBGCt(cA), toBGCt(cB), toBGCt(cC), privateKey.asInstanceOf[DamgardJurikPrivateKey], txtA, txtB )

      sender ! input.getCommonParams
      prover.prove(input)

      self ! Stop

    case Stop => system.terminate()


  }

}

object UserActor {
  def props = Props(new UserActor)
}

class UserActor extends Actor with DJ with ActorLogging{

  import context.dispatcher

  implicit val timeout = Timeout(10.seconds)

  private val secret = BigInteger.valueOf(Math.abs(Random.nextInt() % 10))

  var cA, cB, cC: AsymmetricCiphertext =_

  override def receive = {
    case AskMsg(pk) =>
      sender ! CipherMsg(publicKey, encryptBigInt(pk)(secret))
    case Announce(mA,mB) =>
      cA = mA
      cB = mB
    case CipherMsg(pk, cMult) =>
      cC = cMult
      val mult = decryptBigInt(cMult)
      log.info(s"mult = $mult")
      val channel = new QueueChannel
      val sVC = new SigmaDJProductVerifierComputation()
      val validator = new ZKFromSigmaVerifier(channel, sVC, new SecureRandom)
      for {
        input <- sender ? Challenge(channel, cA, cB, cC)
      } yield {
        validator.verify(input.asInstanceOf[ZKCommonInput])
      }
  }

}

trait DJ {

  private val encryptor = new ScDamgardJurikEnc()

  protected val (publicKey, privateKey) = {
    val p = encryptor.generateKey(new DJKeyGenParameterSpec(128, 40))
    (p.getPublic, p.getPrivate)
  }

  def encryptBigInt(receiverPublicKey: PublicKey)(secret: BigInteger) = {

    //Set private key and party2's public key:
    encryptor.setKey(receiverPublicKey, privateKey)

    //Get the BigInteger value to encrypt, create a BigIntegerPlaintext with it and encrypt the plaintext.
    val plaintext = new BigIntegerPlainText(secret)
    encryptor.encrypt(plaintext)
  }

  def decryptBigInt(
      cipher: AsymmetricCiphertext) = {

    //Set private key and party1's public key:
    // Scapi DJ works setting receiver's public and private keys for decryption
    encryptor.setKey(publicKey, privateKey)

    //Get the ciphertext and decrypt it to get the plaintext
    val plaintext = encryptor.decrypt(cipher).asInstanceOf[BigIntegerPlainText]

    //Get the plaintext element and use it as needed.
    plaintext.getX
  }

}

class QueueChannel extends Channel {

  private val queue = new ConcurrentLinkedDeque[io.Serializable]()

  override def receive() = { println("receiving"); queue.poll}

  override def isClosed = false

  override def close() = ()

  override def send(data: io.Serializable) = {
    println(s" add $data")
    queue.add(data)
  }
}
