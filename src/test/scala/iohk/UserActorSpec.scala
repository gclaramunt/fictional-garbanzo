package iohk

import java.math.BigInteger

import akka.actor.ActorSystem
import akka.testkit.{EventFilter, ImplicitSender, TestKit}
import com.typesafe.config.ConfigFactory
import org.scalatest.prop.Checkers
import org.scalatest.{BeforeAndAfterAll, Matchers, WordSpecLike}

import scala.concurrent.duration._

class UserActorSpec extends TestKit(
  ActorSystem("user-actor-spec",ConfigFactory.parseString("""akka.loggers = ["akka.testkit.TestEventListener"]"""))
) with ImplicitSender with WordSpecLike with Matchers with Checkers with BeforeAndAfterAll {

  override def afterAll {
    TestKit.shutdownActorSystem(system)
  }


  "UserActor" should {

    val alice = system.actorOf(UserActor.props, name = "Alice")
    val dj = new DJ{ val pubK = publicKey}
    val pk = dj.pubK

    "Respond with encrypted message to Ask" in {
      alice ! AskMsg(pk)
      expectMsgType[CipherMsg]
    }

    "Log result when receiving CipherMsg " in {
      alice ! AskMsg(pk)
      val CipherMsg(aPK, _) = receiveOne(1.second)
      alice ! CipherMsg(pk, dj.encryptBigInt(aPK)(BigInteger.valueOf(10)))
      EventFilter(start = "mult =")
    }


  }

}
