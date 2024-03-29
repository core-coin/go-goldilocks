/**
 * @file goldilocks/shake.hxx
 * @copyright
 *   Based on CC0 code by David Leon Gil, 2015 \n
 *   Copyright (c) 2015 Cryptography Research, Inc.  \n
 *   Copyright (c) 2018 the libgoldilocks contributors.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 * @author Mike Hamburg
 * @brief SHA-3-n and SHAKE-n instances, C++ wrapper.
 */

#ifndef __GOLDILOCKS_SHAKE_HXX__
#define __GOLDILOCKS_SHAKE_HXX__

#include <./shake.h>
#include <./secure_buffer.hxx>
#include <sys/types.h>

/** @cond internal */
#if __cplusplus >= 201103L
#define GOLDILOCKS_NOEXCEPT noexcept
#define GOLDILOCKS_DELETE = delete
#else
#define GOLDILOCKS_NOEXCEPT throw()
#define GOLDILOCKS_DELETE
#endif
/** @endcond */

namespace goldilocks {

/**
 * Hash function derived from Keccak
 * FUTURE: throw ProtocolException when hash is misused by calling update() after output().
 */
class KeccakHash {
protected:
    /** @cond internal */
    /** The C-wrapper sponge state */
    goldilocks_keccak_sponge_p wrapped;

    /** Initialize from parameters */
    inline KeccakHash(const goldilocks_kparams_s *params) GOLDILOCKS_NOEXCEPT { goldilocks_sha3_init(wrapped, params); }
    /** @endcond */

public:
    /** Add more data to running hash */
    inline void update(const uint8_t *__restrict__ in, size_t len) GOLDILOCKS_NOEXCEPT { goldilocks_sha3_update(wrapped,in,len); }

    /** Add more data to running hash, C++ version. */
    inline void update(const Block &s) GOLDILOCKS_NOEXCEPT { goldilocks_sha3_update(wrapped,s.data(),s.size()); }

    /** Add more data, stream version. */
    inline KeccakHash &operator<<(const Block &s) GOLDILOCKS_NOEXCEPT { update(s); return *this; }

    /** Same as <<. */
    inline KeccakHash &operator+=(const Block &s) GOLDILOCKS_NOEXCEPT { return *this << s; }

    /** @brief Output bytes from the sponge. */
    inline SecureBuffer output(size_t len) /*throw(std::bad_alloc, LengthException)*/ {
        if (len > max_output_size()) throw LengthException();
        SecureBuffer buffer(len);
        if (GOLDILOCKS_SUCCESS != goldilocks_sha3_output(wrapped,buffer.data(),len)) {
            throw LengthException();
        }
        return buffer;
    }

    /** @brief Output bytes from the sponge. */
    inline SecureBuffer final(size_t len) /*throw(std::bad_alloc, LengthException)*/ {
        if (len > max_output_size()) throw LengthException();
        SecureBuffer buffer(len);
        if (GOLDILOCKS_SUCCESS != goldilocks_sha3_final(wrapped,buffer.data(),len)) {
            throw LengthException();
        }
        return buffer;
    }

    /** @brief Output bytes from the sponge.  Throw LengthException if you've
     * output too many bytes from a SHA-3 instance.
     */
    inline void output(Buffer b) /*throw(LengthException)*/ {
        if (GOLDILOCKS_SUCCESS != goldilocks_sha3_output(wrapped,b.data(),b.size())) {
            throw LengthException();
        }
    }

    /**  @brief Output bytes from the sponge and reinitialize it.  Throw
     * LengthException if you've output too many bytes from a SHA3 instance.
     */
    inline void final(Buffer b) /*throw(LengthException)*/ {
        if (GOLDILOCKS_SUCCESS != goldilocks_sha3_final(wrapped,b.data(),b.size())) {
            throw LengthException();
        }
    }

    /** @brief Return the sponge's default output size. */
    inline size_t default_output_size() const GOLDILOCKS_NOEXCEPT {
        return goldilocks_sha3_default_output_bytes(wrapped);
    }

    /** @brief Return the sponge's maximum output size. */
    inline size_t max_output_size() const GOLDILOCKS_NOEXCEPT {
        return goldilocks_sha3_max_output_bytes(wrapped);
    }

    /** Output the default number of bytes. */
    inline SecureBuffer output() /*throw(std::bad_alloc,LengthException)*/ {
        return output(default_output_size());
    }

    /** Output the default number of bytes, and reset hash. */
    inline SecureBuffer final() /*throw(std::bad_alloc,LengthException)*/ {
        return final(default_output_size());
    }

    /** Reset the hash to the empty string */
    inline void reset() GOLDILOCKS_NOEXCEPT { goldilocks_sha3_reset(wrapped); }

    /** Destructor zeroizes state */
    inline ~KeccakHash() GOLDILOCKS_NOEXCEPT { goldilocks_sha3_destroy(wrapped); }
};

/** Fixed-output-length SHA3 */
template<int bits> class SHA3 : public KeccakHash {
private:
    /** Get the parameter template block for this hash */
    static inline const struct goldilocks_kparams_s *get_params();

public:
    /** Number of bytes of output */
    static const size_t MAX_OUTPUT_BYTES = bits/8;

    /** Number of bytes of output */
    static const size_t DEFAULT_OUTPUT_BYTES = bits/8;

    /** Initializer */
    inline SHA3() GOLDILOCKS_NOEXCEPT : KeccakHash(get_params()) {}

    /** Hash bytes with this SHA3 instance.
     * @throw LengthException if nbytes > MAX_OUTPUT_BYTES
     */
    static inline SecureBuffer hash(const Block &b, size_t nbytes = MAX_OUTPUT_BYTES) /*throw(std::bad_alloc, LengthException)*/ {
        if (nbytes > MAX_OUTPUT_BYTES) {
            throw LengthException();
        }
        SHA3 s; s += b; return s.output(nbytes);
    }
};

/** Variable-output-length SHAKE */
template<int bits>
class SHAKE : public KeccakHash {
private:
    /** Get the parameter template block for this hash */
    static inline const struct goldilocks_kparams_s *get_params();

public:
    /** Number of bytes of output */
#if __cplusplus >= 201103L
    static const size_t MAX_OUTPUT_BYTES = SIZE_MAX;
#else
    static const size_t MAX_OUTPUT_BYTES = (size_t)-1;
#endif

    /** Default number of bytes to output */
    static const size_t DEFAULT_OUTPUT_BYTES = bits/4;

    /** Initializer */
    inline SHAKE() GOLDILOCKS_NOEXCEPT : KeccakHash(get_params()) {}

    /** Hash bytes with this SHAKE instance */
    static inline SecureBuffer hash(const Block &b, size_t outlen) /*throw(std::bad_alloc)*/ {
        SHAKE s; s += b; return s.output(outlen);
    }
};

/** @cond internal */
template<> inline const struct goldilocks_kparams_s *SHAKE<128>::get_params() { return &GOLDILOCKS_SHAKE128_params_s; }
template<> inline const struct goldilocks_kparams_s *SHAKE<256>::get_params() { return &GOLDILOCKS_SHAKE256_params_s; }
template<> inline const struct goldilocks_kparams_s *SHA3<224>::get_params() { return  &GOLDILOCKS_SHA3_224_params_s; }
template<> inline const struct goldilocks_kparams_s *SHA3<256>::get_params() { return  &GOLDILOCKS_SHA3_256_params_s; }
template<> inline const struct goldilocks_kparams_s *SHA3<384>::get_params() { return  &GOLDILOCKS_SHA3_384_params_s; }
template<> inline const struct goldilocks_kparams_s *SHA3<512>::get_params() { return  &GOLDILOCKS_SHA3_512_params_s; }
/** @endcond */

} /* namespace goldilocks */

#undef GOLDILOCKS_NOEXCEPT
#undef GOLDILOCKS_DELETE

#endif /* __GOLDILOCKS_SHAKE_HXX__ */
