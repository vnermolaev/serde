// @file:UseSerializers(PublicKeyAsSurrogate::class)
// @file:UseSerializers(ListSerde::class)
// @file:UseSerializers(RSAPublicKeyImplSerde::class)

import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationStrategy
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.buildClassSerialDescriptor
import kotlinx.serialization.descriptors.element
import kotlinx.serialization.encoding.AbstractDecoder
import kotlinx.serialization.encoding.AbstractEncoder
import kotlinx.serialization.encoding.CompositeDecoder
import kotlinx.serialization.encoding.CompositeEncoder
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.modules.SerializersModule
import kotlinx.serialization.modules.polymorphic
import kotlinx.serialization.serializer
import sun.security.rsa.RSAPublicKeyImpl
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInput
import java.io.DataInputStream
import java.io.DataOutput
import java.io.DataOutputStream
import java.security.KeyPairGenerator
import java.security.PublicKey
import java.security.SecureRandom
import java.text.SimpleDateFormat
import java.util.Date

class LW<T>(val list: List<T>)

@Serializable
@SerialName("RSAPublicKeyImpl")
private class RSAPublicKeySurrogate(val encoded: ByteArray)


object RSAPublicKeySerializer : KSerializer<RSAPublicKeyImpl> {
    override val descriptor = RSAPublicKeySurrogate.serializer().descriptor

    override fun serialize(encoder: Encoder, value: RSAPublicKeyImpl) {
        encoder.encodeSerializableValue(
            RSAPublicKeySurrogate.serializer(),
            RSAPublicKeySurrogate(value.encoded)
        )
    }

    override fun deserialize(decoder: Decoder): RSAPublicKeyImpl {
        val surrogate = decoder.decodeSerializableValue(RSAPublicKeySurrogate.serializer())
        return RSAPublicKeyImpl(surrogate.encoded)
    }
}


class DataOutputEncoder(val output: DataOutput, val totalLength: Int = 10) : AbstractEncoder() {
    private val baSerializer = serializer<ByteArray>()

    override val serializersModule = SerializersModule {
        polymorphic(PublicKey::class) {
            subclass(RSAPublicKeyImpl::class, RSAPublicKeySerializer)
        }
    }

    override fun encodeBoolean(value: Boolean) = output.writeByte(if (value) 1 else 0)
    override fun encodeByte(value: Byte) = output.writeByte(value.toInt())
    override fun encodeShort(value: Short) = output.writeShort(value.toInt())
    override fun encodeInt(value: Int) = output.writeInt(value)
    override fun encodeLong(value: Long) = output.writeLong(value)
    override fun encodeFloat(value: Float) = output.writeFloat(value)
    override fun encodeDouble(value: Double) = output.writeDouble(value)
    override fun encodeChar(value: Char) = output.writeChar(value.toInt())
    override fun encodeString(value: String) = output.writeUTF(value)
    override fun encodeEnum(enumDescriptor: SerialDescriptor, index: Int) = output.writeInt(index)

    override fun beginCollection(descriptor: SerialDescriptor, collectionSize: Int): CompositeEncoder {
        encodeInt(collectionSize)
        return this
    }

    override fun <T> encodeSerializableValue(serializer: SerializationStrategy<T>, value: T) {
        when (value) {
            is List<*> -> {
                println("LIST!!!")
                // encodeSerializableValue()
            }
        }

        serializer.serialize(this, value)
    }

    override fun encodeNull() = encodeBoolean(false)
    override fun encodeNotNullMark() = encodeBoolean(true)
}

fun <T> encodeTo(output: DataOutput, serializer: SerializationStrategy<T>, value: T) {
    val encoder = DataOutputEncoder(output)
    encoder.encodeSerializableValue(serializer, value)
}

inline fun <reified T> encodeTo(output: DataOutput, value: T) {
    val serializer = serializer<T>()
    encodeTo(output, serializer, value)
}

class DataInputDecoder(val input: DataInput, var elementsCount: Int = 0) : AbstractDecoder() {
    private val baSerializer = serializer<ByteArray>()

    private var elementIndex = 0

    override val serializersModule = SerializersModule {
        polymorphic(PublicKey::class) {
            subclass(RSAPublicKeyImpl::class, RSAPublicKeySerializer)
        }
    }

    override fun decodeBoolean(): Boolean = input.readByte().toInt() != 0
    override fun decodeByte(): Byte = input.readByte()
    override fun decodeShort(): Short = input.readShort()
    override fun decodeInt(): Int = input.readInt()
    override fun decodeLong(): Long = input.readLong()
    override fun decodeFloat(): Float = input.readFloat()
    override fun decodeDouble(): Double = input.readDouble()
    override fun decodeChar(): Char = input.readChar()
    override fun decodeString(): String = input.readUTF()

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

//////////////////////
@Serializable
data class User(val id: PublicKey)

@Serializable
data class GenericUser<U>(val id: U)

inline fun <reified T> test(
    data: T,
    serde: KSerializer<T>? = null
) {
    println("Data:\n$data\n")
    //--------

    val output = ByteArrayOutputStream()

    if (serde != null) {
        encodeTo(DataOutputStream(output), serde, data)
    } else {
        encodeTo(DataOutputStream(output), data)
    }

    val bytes = output.toByteArray()
    println("Serialized:\n${bytes.joinToString(",")}\n")
    // --------

    val input = ByteArrayInputStream(bytes)

    val obj = if (serde != null) {
        decodeFrom<T>(DataInputStream(input), serde)
    } else {
        decodeFrom<T>(DataInputStream(input))
    }
    println("Deserialized:\n$obj\n")
}

fun main() {
    // Generate some public key
    val pk = getRSA()

    // Simple inclusion of a public key
    val u = User(pk)
    test(u)

    // Inclusion of PublicKey as a generic
    //val gu = GenericUser(pk)
    // TODO: this only works with specifying a serde strategy.
    // test(gu, GenericUser.serializer(PKSerde))
    // TODO: explicit typing does not help
    // test<GenericUser<PublicKey>>(gu)
    // test(gu)

    // testList()

//    testML()
}

fun getRSA(): PublicKey {
    val generator = KeyPairGenerator.getInstance("RSA")
    generator.initialize(2048, SecureRandom())
    return generator.genKeyPair().public
}

// Implement a PublicKey surrogate and respective serde.
@Serializable
class PKSurrogate(val kind: KeyKind, val encoded: ByteArray) {
    enum class KeyKind {
        RSA
    }

    companion object {
        fun RSA(key: PublicKey) = PKSurrogate(KeyKind.RSA, key.encoded)
    }
}

// object PKSurrogateSerde: KSerializer<PKSurrogate> {
//     private val baSerializer = serializer<ByteArray>()
//
//     override val descriptor: SerialDescriptor = buildClassSerialDescriptor() {
//         element<PKSurrogate.KeyKind>("")
//         element<ByteArray>("")
//     }
//
//     override fun deserialize(decoder: Decoder): PKSurrogate {
//         TODO("Not yet implemented")
//     }
//
//     override fun serialize(encoder: Encoder, value: PKSurrogate) {
//         encoder.encodeEnum(
//             PKSurrogate.KeyKind.serializer().descriptor,
//             value.kind.ordinal
//         )
//         baSerializer.serialize(encoder, value.encoded)
//     }
// }

object RSAPublicKeyImplSerde : KSerializer<RSAPublicKeyImpl> {
    private val strategy = PKSurrogate.serializer()
    override val descriptor: SerialDescriptor = strategy.descriptor

    override fun serialize(encoder: Encoder, value: RSAPublicKeyImpl) {
        encoder.encodeSerializableValue(strategy, PKSurrogate.RSA(value))
    }

    override fun deserialize(decoder: Decoder): RSAPublicKeyImpl {
        val surrogate = decoder.decodeSerializableValue(strategy)
        return RSAPublicKeyImpl(surrogate.encoded)
    }
}

object PKSerde : KSerializer<PublicKey> {
    private val strategy = PKSurrogate.serializer()
    override val descriptor: SerialDescriptor = strategy.descriptor

    override fun serialize(encoder: Encoder, value: PublicKey) {
        encoder.encodeSerializableValue(strategy, PKSurrogate.RSA(value))
    }

    override fun deserialize(decoder: Decoder): PublicKey {
        val surrogate = decoder.decodeSerializableValue(strategy)
        return when (surrogate.kind) {
            PKSurrogate.KeyKind.RSA -> RSAPublicKeyImpl(surrogate.encoded)
        }
    }
}

///
object DateAsLongSerializer : KSerializer<Date> {
    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("Date", PrimitiveKind.LONG)
    override fun serialize(encoder: Encoder, value: Date) = encoder.encodeLong(value.time)
    override fun deserialize(decoder: Decoder): Date = Date(decoder.decodeLong())
}

object ListSerializer : KSerializer<List<Int>> {
    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("Date", PrimitiveKind.LONG)
    override fun serialize(encoder: Encoder, value: List<Int>) = encoder.encodeInt(value.size)
    override fun deserialize(decoder: Decoder): List<Int> = listOf(0)
}

@Serializable
data class ML(@Serializable(with = ListSerializer::class) val list: List<Int>)

fun testML() {
    val data = ML(listOf(1, 2, 3))
    val output = ByteArrayOutputStream()

    encodeTo(DataOutputStream(output), data)

    val bytes = output.toByteArray()
    println("Serialized:\n${bytes.joinToString(",")}\n")
    // // --------
    //
    // val input = ByteArrayInputStream(bytes)
    //
    // val obj = if (serde != null) {
    //     decodeFrom(DataInputStream(input), serde)
    // } else {
    //     decodeFrom(DataInputStream(input))
    // }
    // println("Deserialized:\n$obj\n")
}


@Serializable
data class L(
    // @Serializable(with = ListSerde::class)
    val list: List<Int>
    // @Serializable(with = DateAsLongSerializer::class)
    // val stableReleaseDate: Date
)

fun testList() {
    val kotlin10ReleaseDate = SimpleDateFormat("yyyy-MM-ddX").parse("2016-02-15+00")
    val serde: KSerializer<L>? = null
    // val data = L(kotlin10ReleaseDate)
    val data = L(listOf(1, 2, 3))
    println("Data:\n$data\n")
    //--------

    val output = ByteArrayOutputStream()

    if (serde != null) {
        encodeTo(DataOutputStream(output), serde, data)
    } else {
        encodeTo(DataOutputStream(output), data)
    }

    val bytes = output.toByteArray()
    println("Serialized:\n${bytes.joinToString(",")}\n")
    // --------

    val input = ByteArrayInputStream(bytes)

    val obj = if (serde != null) {
        decodeFrom(DataInputStream(input), serde)
    } else {
        decodeFrom(DataInputStream(input))
    }
    println("Deserialized:\n$obj\n")
}

class ListSerde : KSerializer<List<Int>> {
    override val descriptor: SerialDescriptor = buildClassSerialDescriptor("list") {
        element<Int>("total")
        element<Int>("actual")
        element<ByteArray>("bytes")
    }

    override fun deserialize(decoder: Decoder): List<Int> {
        TODO("Not yet implemented")
    }

    override fun serialize(encoder: Encoder, value: List<Int>) {
        println("HI")
    }
}