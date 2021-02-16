@file:UseSerializers(PublicKeyAsByteArraySerializer::class)

import kotlinx.serialization.*
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.descriptors.*
import kotlinx.serialization.encoding.*
import kotlinx.serialization.modules.*
import sun.security.rsa.RSAPublicKeyImpl
import java.io.*
import java.nio.ByteBuffer
import java.security.KeyPairGenerator
import java.security.PublicKey
import java.security.SecureRandom
import kotlin.random.Random

class DataOutputEncoder(val output: DataOutput) : AbstractEncoder() {
    private val baSerializer = ListSerializer(Byte.serializer())

    override val serializersModule: SerializersModule = EmptySerializersModule
    override fun encodeBoolean(value: Boolean) = output.writeByte(if (value) 1 else 0)
    override fun encodeByte(value: Byte) = output.writeByte(value.toInt())
    override fun encodeShort(value: Short) = output.writeShort(value.toInt())
    override fun encodeInt(value: Int) = output.writeInt(value)
    override fun encodeLong(value: Long) = output.writeLong(value)
    override fun encodeFloat(value: Float) = output.writeFloat(value)
    override fun encodeDouble(value: Double) = output.writeDouble(value)
    override fun encodeChar(value: Char) = output.writeChar(value.toInt())
    override fun encodeString(value: String) {
        // this works!
        // this.encodeSerializableValue(StringAsSurrogate, value)

        // construct: actual (4b) + (value + trash) (10b)
        val encoding = ByteBuffer.allocate(4).putInt(value.length).array() +
            value.toByteArray() + Random.nextBytes(10 - value.length)

        baSerializer.serialize(this, encoding.toList())
    }
    override fun encodeEnum(enumDescriptor: SerialDescriptor, index: Int) = output.writeInt(index)

    override fun beginCollection(descriptor: SerialDescriptor, collectionSize: Int): CompositeEncoder {
        encodeInt(collectionSize)
        return this
    }

    override fun encodeNull() = encodeBoolean(false)
    override fun encodeNotNullMark() = encodeBoolean(true)
}

fun <T> encodeTo(output: DataOutput, serializer: SerializationStrategy<T>, value: T) {
    val encoder = DataOutputEncoder(output)
    encoder.encodeSerializableValue(serializer, value)
}

inline fun <reified T> encodeTo(output: DataOutput, value: T) = encodeTo(output, serializer(), value)

class DataInputDecoder(val input: DataInput, var elementsCount: Int = 0) : AbstractDecoder() {
    private val baSerializer = ListSerializer(Byte.serializer())

    private var elementIndex = 0
    override val serializersModule: SerializersModule = EmptySerializersModule
    override fun decodeBoolean(): Boolean = input.readByte().toInt() != 0
    override fun decodeByte(): Byte = input.readByte()
    override fun decodeShort(): Short = input.readShort()
    override fun decodeInt(): Int = input.readInt()
    override fun decodeLong(): Long = input.readLong()
    override fun decodeFloat(): Float = input.readFloat()
    override fun decodeDouble(): Double = input.readDouble()
    override fun decodeChar(): Char = input.readChar()
    override fun decodeString(): String {
        // this works!
        // return this.decodeSerializableValue(StringAsSurrogate)

        val bytes = baSerializer.deserialize(this).toByteArray()
        val length = ByteBuffer.wrap(bytes, 0, 4).int
        return String(bytes.sliceArray(4 until 4 + length))
    }

    override fun decodeEnum(enumDescriptor: SerialDescriptor): Int = input.readInt()

    override fun decodeElementIndex(descriptor: SerialDescriptor): Int {
        if (elementIndex == elementsCount) return CompositeDecoder.DECODE_DONE
        return elementIndex++
    }

    override fun beginStructure(descriptor: SerialDescriptor): CompositeDecoder =
        DataInputDecoder(input, descriptor.elementsCount)

    override fun decodeSequentially(): Boolean = true

    override fun decodeCollectionSize(descriptor: SerialDescriptor): Int =
        decodeInt().also { elementsCount = it }

    override fun decodeNotNullMark(): Boolean = decodeBoolean()
}

fun <T> decodeFrom(input: DataInput, deserializer: DeserializationStrategy<T>): T {
    val decoder = DataInputDecoder(input)
    return decoder.decodeSerializableValue(deserializer)
}

inline fun <reified T> decodeFrom(input: DataInput): T = decodeFrom(input, serializer())

@Serializable
data class Move(
    val from: String,
    val to: String,
    // val owner: PublicKey,
    val amount: Int
    )

@Serializable
data class Issue(
    val name: String,
    val owner: PublicKey,
    val amount: Int
)

@Serializable(with = EnvelopeSerializer::class) // <- this is for deserialization
sealed class Envelope(val id: Int) {
    // TODO Improvement: have an inner type bound to be serializable
    // and pass the inner of respective types inside
    @Serializable(with = EnvelopeSerializer::class) // <- this is for serialization
    class OfMove(val inner: Move): Envelope(0)

    @Serializable(with = EnvelopeSerializer::class) // <- this is for serialization
    class OfIssue(val inner: Issue): Envelope(1)
}

object EnvelopeSerializer : KSerializer<Envelope> {
    private val baSerializer = ListSerializer(Byte.serializer())

    override val descriptor: SerialDescriptor = buildClassSerialDescriptor("envelope") {
        element<Int>("type")
        element<ByteArray>("inner")
    }

    override fun serialize(encoder: Encoder, value: Envelope) {
        val output = ByteArrayOutputStream()

        // TODO see todo inside Envelope
        when (value) {
            is Envelope.OfMove -> encodeTo(DataOutputStream(output), value.inner)
            is Envelope.OfIssue -> encodeTo(DataOutputStream(output), value.inner)
        }

        encoder.encodeInt(value.id)
        baSerializer.serialize(encoder, output.toByteArray().toList())
    }

    override fun deserialize(decoder: Decoder): Envelope {
        val kind = decoder.decodeInt()
        val bytes = baSerializer.deserialize(decoder).toByteArray()

        val input = ByteArrayInputStream(bytes)

        return when (kind) {
            0 -> Envelope.OfMove(decodeFrom(DataInputStream(input)))
            1 -> Envelope.OfIssue(decodeFrom(DataInputStream(input)))
            else -> error("sad")
        }
    }
}

@Serializable
data class Project(val name: String, val language: String, val pk: PublicKey)

fun main() {
    // // *** Simple Use case -->
    // val data = Project("aa", "bb", getPk())
    // println(data)
    //
    // val output = ByteArrayOutputStream()
    // encodeTo(DataOutputStream(output), data)
    // val bytes = output.toByteArray()
    // // println(bytes.toAsciiHexString())
    // println(bytes.joinToString(","))
    //
    // val input = ByteArrayInputStream(bytes)
    // val obj = decodeFrom<Project>(DataInputStream(input))
    // println(obj)
    // <--

    // // *** Envelopes -->
    val move = Move(
        from = "A",
        to = "B",
        // owner = getPk(),
        amount = 10
    )
    val envelope = Envelope.OfMove(move)
    println("In: ${envelope.inner}")

    val output = ByteArrayOutputStream()
    encodeTo(DataOutputStream(output), envelope)
    val bytes = output.toByteArray()
    println(bytes.joinToString(","))

    val input = ByteArrayInputStream(bytes)
    when (decodeFrom<Envelope>(DataInputStream(input))) {
        is Envelope.OfMove -> println("Out: ${envelope.inner}")
        is Envelope.OfIssue -> println("Out: ${envelope.inner}")
    }
}

fun getPk(): PublicKey {
    val generator = KeyPairGenerator.getInstance("RSA")
    generator.initialize(2048, SecureRandom())
    return generator.genKeyPair().public
}


object PublicKeyAsByteArraySerializer : KSerializer<PublicKey> {
    private val baSerializer = ListSerializer(Byte.serializer())
    override val descriptor: SerialDescriptor = baSerializer.descriptor
    override fun serialize(encoder: Encoder, value: PublicKey) {
        baSerializer.serialize(encoder, value.encoded.toList())
    }
    override fun deserialize(decoder: Decoder): PublicKey {
        val bytes = baSerializer.deserialize(decoder).toByteArray()
        return RSAPublicKeyImpl(bytes)
    }
}

@Serializable
data class StringSurrogate(val actual: Int, val data: ByteArray)

object StringAsSurrogate: KSerializer<String> {
    override val descriptor: SerialDescriptor = StringSurrogate.serializer().descriptor

    override fun deserialize(decoder: Decoder): String {
        val surrogate = decoder.decodeSerializableValue(StringSurrogate.serializer())
        return String(surrogate.data.sliceArray(0 until surrogate.actual))
    }

    override fun serialize(encoder: Encoder, value: String) {
        val surrogate = StringSurrogate(
            value.length,
            value.toByteArray() + Random.nextBytes(10 - value.length)
        )

        encoder.encodeSerializableValue(StringSurrogate.serializer(), surrogate)
    }
}

fun ByteArray.toAsciiHexString() = joinToString("") {
    if (it in 32..127) it.toChar().toString() else
        "{${it.toUByte().toString(16).padStart(2, '0').toUpperCase()}}"
}