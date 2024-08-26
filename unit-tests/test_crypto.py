import io
from unittest import TestCase

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from keepercommander import crypto, utils


class TestCrypto(TestCase):
    def test_stream_decrypter(self):
        data = bytearray(999)
        for i in range(len(data)):
            data[i] = i & 0xff

        key = utils.generate_aes_key()

        crypter = crypto.StreamCrypter()
        crypter.key = key
        crypter.is_gcm = False

        encrypted_data = bytearray()
        with crypter.set_stream(io.BytesIO(data), True) as cs:
            while True:
                buffer = cs.read(1024)
                if not buffer:
                    break
                encrypted_data.extend(buffer)
        self.assertEqual(crypter.bytes_read, len(data))

        decrypted_data = bytearray()
        with crypter.set_stream(io.BytesIO(encrypted_data), False) as cs:
            while True:
                buffer = cs.read(1024)
                if not buffer:
                    break
                decrypted_data.extend(buffer)

        self.assertEqual(decrypted_data, data)

    def test_decrypt_aes_v1(self):
        data = utils.base64_url_decode('KvsOJmE4JNK1HwKSpkBeR5R9YDms86uOb3wjNvc4LbUnZhKQtDxWifgA99tH2ZuP')
        key = utils.base64_url_decode('pAZmcxEoV2chXsFQ6bzn7Lop8yO4F8ERIuS7XpFtr7Y')
        data = crypto.decrypt_aes_v1(data, key)
        self.assertEqual(data, utils.base64_url_decode('6lf4FGVyhDRnRhJ91TrahjIW8lTqGA'))

    def test_encrypt_aes_v2(self):
        key = utils.base64_url_decode('c-EeCGlAO7F9QoJThlFBrhSCLYMe1H6GtKP-rezDnik')
        data = utils.base64_url_decode('nm-8mRG7xYwUG2duaOZzw-ttuqfetWjVIzoridJF0EJOGlDLs1ZWQ7F9mOJ0Hxuy' +
                                       'dFyojxdxVo1fGwbfwf0Jew07HhGGE5UZ_s57rQvhizDW3F3z9a7EqHRon0EilCbMhIzE')
        nonce = utils.base64_url_decode('Nt9_Y37C_43eRCRQ')
        enc_data = crypto.encrypt_aes_v2(data, key, nonce)
        expected_data = utils.base64_url_decode('Nt9_Y37C_43eRCRQCptb64zFaJVLcXF1udabOr_fyGXkpjpYeCAI7zVQD4JjewB' +
                                                'CP1Xp7D6dx-pxdRWkhDEnVhJ3fzezi8atmmzvf2ICfkDK0IHHB8iNSx_R1Ru8Tozb-IdavT3wKi7nKSJLDdt-dk-Mw7bCewpZtg4wY-1UQw')
        self.assertEqual(enc_data, expected_data)

        dec_data = crypto.decrypt_aes_v2(enc_data, key)
        self.assertEqual(dec_data, data)

    def test_encrypt_aes_v1(self):
        iv = utils.base64_url_decode('KvsOJmE4JNK1HwKSpkBeRw')
        block = utils.base64_url_decode('6lf4FGVyhDRnRhJ91TrahjIW8lTqGA')
        key = utils.base64_url_decode('pAZmcxEoV2chXsFQ6bzn7Lop8yO4F8ERIuS7XpFtr7Y')
        enc = crypto.encrypt_aes_v1(block, key, iv)
        encoded = utils.base64_url_encode(enc)
        self.assertEqual(encoded, 'KvsOJmE4JNK1HwKSpkBeR5R9YDms86uOb3wjNvc4LbUnZhKQtDxWifgA99tH2ZuP')

    def test_encrypt_rsa(self):
        data = crypto.get_random_bytes(100)
        puk = crypto.load_rsa_public_key(utils.base64_url_decode(_test_public_key))
        enc_data = crypto.encrypt_rsa(data, puk)
        prk = crypto.load_rsa_private_key(utils.base64_url_decode(_test_private_key))
        dec_data = crypto.decrypt_rsa(enc_data, prk)
        self.assertEqual(data, dec_data)

    def test_decrypt_rsa_short_ciphertext(self):
        def decrypt_message(encrypted_hex, apply_padding=False):
            data = bytes.fromhex(encrypted_hex)
            result = None
            try:
                plaintext_bytes = crypto.decrypt_rsa(data, rsa_key, apply_padding=apply_padding)
                result = plaintext_bytes.decode()
            finally:
                return result

        key_hex = ('308204a2020100028201007b3101c3c3d9e5c3e221c9bf2b12007f7c18a8b9732dd304760d0900221d0391a1c318410'
                   '74a52a9f5c73cda7114f042834990d7218d31601d838115b7dd5b6685502652f1453c940f499918781b335395658316'
                   '9795f9971c4431492378ca1e15f625e68b8a7678e4192b265e8517276397901517a6f0bc79a8367f5218346f3d8823a'
                   '336b1cd7370f76ecdc12f09fe92b8f0f723d086a64cdedc46af0c99ac5b5b050df9dd8b1cac21a529b3fd95086178a9'
                   'bcbfff3da92aa377aa344dca4469524594ef18061bb10452a309efdad9cc421ac5a9a833960708c32543c84d1064136'
                   '769c0e3156bc1b835ac17421a3dcb01b82b88ab59157f1bbe53c5a44a3702030100010282010068b2def0157d1464e5'
                   'c497a54ca2b11fa84580e8943666f88ca84974fe8930264e97f3fe1887173871b59247890225ac31ce8d35f9c2f92ad'
                   'a0a90e3f76f3f2623b959c8f65b44c0053a24ce820d8412ce8f06d9659dc611a2a96645e5cadbe4b3ff8e78a131ddbc'
                   'a307acffa02776e5382471052c23eac814915d37da7acddc5ebea2c9c84cabb8ad50ce297313131eacf52864bf2f546'
                   '078da3bed3bc03b7b3aaf881c17fff87b81ba201f21377dc73f67835da7179cafa273e7594a757d3ad7c6b6aed07b3a'
                   '993a0940514a7d8fe7b65492897dae020342126f0d95171fc33cb56205881df9a7b21d7b87c737902968b13d97a8593'
                   'b9973682b45595b34c902818100ecc10d7ebb81328272dd4dae731871e3649f5e5630260269ec91e5ccae9faec8459f'
                   '62c6bb4f950527e1c248b7a5ea5f3b8d1418d54735e1768bdb0b2b0472cee679a106d342cf7932c3495818e5484850e'
                   'cd2eb075743bb3c977b23aa1c9227fa99ab5612dc34824d78f6a86bc522a98115170beb8955e907aceff1594fe5b302'
                   '8181008534ab6d754cd5a7c6a94ac8f98b69c6118b7dabb8f5965291e16688613da8b6b60ae528897e82f02b0b7ee12'
                   'e89dec709333ae8438c0f69c3327ed8ba5243a00c5d55ec0b31d595d64ccaa51c0084db54d34ea7f13abe5deb06a1cd'
                   '02bb06d6c2bd1fd9a1478ae7f03c71b304a217ca012311bbdae1e586871923ee0e2e0f6d0281802b24f7379c25ec357'
                   '7873acbcaafaeb978b1ce3838a804929708f36ebc77df1b220cecac38a04510de76b6b817b785a17b31b772db13120f'
                   '9751df4606bdd5ca3c97f7af4dba84229b0c9986136b5d23c8938fd042d335459ec2202f9ca57e4108db0e2d2e5cb0b'
                   '8fa334c07df33daa03724c7c16557eeaefbb61937cb45d31f0281807c95f68039e5d32f48afae32aab3aa0a86fe605b'
                   'ec72465693faad5b81179a64c97f073612e330b4508e3fed7d099643b267280174abdafea082ea00eac3665c9b33f0d'
                   '904df6754ed4a857e47e274606fc5f31b409420d8d6a92d4c01f1cb43b28010fa0bce4e2d0094880357a2037dfbf240'
                   'f3e294c5883d735617a14b934102818100e8ebbea878b36ae483715b83255c6150443f1afff2cd105375df0b0448bab'
                   '92d957d455036b32fc25b36f926bb3f0aef2e60ead9d731911bc59109319fed35b11ffff3ca44656e64589774f25a4f'
                   '40c4c79adb954b74e0d0bf9b1923117fd70a755d28f56c1f6e5b148366d9136be4a07302d90d4f7fe8f0b1ccb1b617f'
                   '3ca83')
        key = bytes.fromhex(key_hex)
        rsa_key = crypto.load_rsa_private_key(key)  # type: RSAPrivateKey
        plaintext = 'This is a message'

        # The following value is a sample output of jsbn-rsa encryption, which can sometimes give us length < 2048-bit
        ciphertext_hex = ('ea6ef330b9e96b078374f892127e4adda7c27451abc3d4198e74b1a6a779afd82c9c1ca206bd6055f8238e3fa77b'
                          '62d7e9a6963a148f129c9371d9aad41a99d98b336e084f1b8e09e9f3f80595fc0991ce11269c57accb021307ec45'
                          '570a2061f7d7ddb3478eed0c57f464371eccfe90e13e78e7bc016cc5fd80624140497eb91d83a1d4661b8aa7c08d'
                          '7cc90373c891ccda46e2e01351c8944c2170e3aad46cfc97511469c10913169e33c3febccee5a2e0cfa5c8958741'
                          '3a3b7f712b89ffc60c8572d89b70ba45cc6158e96ffd37dc5f685863eff00df5ccdbe7c01ad91316286ee0793553'
                          '0015cbc13827ff1975b305cf132985b5f02fa7a8dd57d96533')

        # If no left-padding of 0s is applied to this ciphertext, we expect the decryption to fail
        self.assertIsNone(
            decrypt_message(ciphertext_hex, apply_padding=False)
        )
        # Otherwise, we expect it to give us the original plaintext message
        self.assertEqual(
            decrypt_message(ciphertext_hex, apply_padding=True),
            plaintext
        )

    def test_ec_encryption(self):
        private_key = crypto.load_ec_private_key(utils.base64_url_decode(_test_ec_private_key))
        decrypted_data = crypto.decrypt_ec(utils.base64_url_decode(_test_ec_encrypted_data), private_key)
        data = utils.base64_url_decode(_test_random_data)
        self.assertEqual(decrypted_data, data)

    def test_derive_key_hash_v1(self):
        password = 'q2rXmNBFeLwAEX55hVVTfg'
        salt = utils.base64_url_decode('Ozv5_XSBgw-XSrDosp8Y1A')
        iterations = 1000
        expected_key = utils.base64_url_decode('nu911pKhOIeX_lToXa4uIUuMPg1pj_3ZGpGmd7OjvRs')
        key_hash = crypto.derive_keyhash_v1(password, salt, iterations)
        self.assertEqual(key_hash, expected_key)

    def test_derive_key_hash_v2(self):
        password = 'q2rXmNBFeLwAEX55hVVTfg'
        salt = utils.base64_url_decode('Ozv5_XSBgw-XSrDosp8Y1A')
        iterations = 1000
        expected_key = utils.base64_url_decode('rXE9OHv_gcvUHdWuBIkyLsRDXT1oddQCzf6PrIECl2g')
        domain = '1oZZl0fKjU4'
        key_hash = crypto.derive_keyhash_v2(domain, password, salt, iterations)
        self.assertEqual(key_hash, expected_key)

    def test_password_score(self):
        self.assertEqual(utils.password_score('!@#$%^&*()'), 92)
        self.assertEqual(utils.password_score('aZkljfzsnmp4w9058dsqln5yf(&*))(*)(345'), 100)
        self.assertEqual(utils.password_score('c3>^sxuKZ[Ndyo(OBE14'), 100)
        self.assertEqual(utils.password_score('AAAbbbCCC11'), 38)
        self.assertEqual(utils.password_score('password'), 8)


_test_random_data = \
    'cKGoVph_X0NKjk8jQgxyQWRElUY7IsbbIJaRcJVlnOb7AchFiY-izmTTOlgArwIqAxKDKSRAWx2Q1pX' \
    'mWUUoEVKwFE9B2pLUi_GrTQu_hPEm6HjinwJaUPql-kqDfvGLiX6yBw'

_test_ec_private_key = 'HIIeyuuRkVGvhtax8mlX7fangaC6DKa2R8VAg5AAtBY'

_test_ec_encrypted_data = \
    'BMObx0eJO48N3Fg-2rQzVzppGi51kkxCM3KTRr2Zqe_q1kS8waisb2X9mDMnGKCtJqJLsVdTYsCn_BZ' \
    'zrbXO8846fMBqc1fKnOIBnxc_YIvTU9iKdx3vKgonOrPkyLMu273YQx8MpP-_FUjymRG7Rf4J0BIroP' \
    '5ndvaC6bzDmZGS-KLP8zO7oY7oNgeOI9Tj3AXCW65No2QzvGsppEHK1DcPpL8dh4RK2vt8Hh9Udj86Y' \
    'd-pi11AXusnzysl6cwzWA'

_test_public_key = "MIIBCgKCAQEAqR0AjmBXo371pYmvS1NM8nXlbAv5qUbPYuV6KVwKjN3T8WX5K6HD" \
                   "Gl3-ylAbI02vIzKue-gDbjo1wUGp2qhANc1VxllLSWnkJmwbuGUTEWp4ANjusoMh" \
                   "PvEwna1XPdlrSMdsKokjbP9xbguPdvXx5oBaqArrrGEg-36Vi7miA_g_UT4DKcry" \
                   "glD4Xx0H9t5Hav-frz2qcEsyh9FC0fNyon_uveEdP2ac-kax8vO5EeVfBzOdw-WP" \
                   "aBtUO1h7rSZ6xKOm6x1OahNTUFy7Cgm038JuMwHChTK29H9EOlqbOOuzYA1ENzL8" \
                   "8hELpe-kl4RmpNS94BJDssikFFbjoiAVfwIDAQAB"

_test_private_key = "MIIEogIBAAKCAQEAqR0AjmBXo371pYmvS1NM8nXlbAv5qUbPYuV6KVwKjN3T8WX5" \
                    "K6HDGl3-ylAbI02vIzKue-gDbjo1wUGp2qhANc1VxllLSWnkJmwbuGUTEWp4ANju" \
                    "soMhPvEwna1XPdlrSMdsKokjbP9xbguPdvXx5oBaqArrrGEg-36Vi7miA_g_UT4D" \
                    "KcryglD4Xx0H9t5Hav-frz2qcEsyh9FC0fNyon_uveEdP2ac-kax8vO5EeVfBzOd" \
                    "w-WPaBtUO1h7rSZ6xKOm6x1OahNTUFy7Cgm038JuMwHChTK29H9EOlqbOOuzYA1E" \
                    "NzL88hELpe-kl4RmpNS94BJDssikFFbjoiAVfwIDAQABAoIBABB9KW64ahMg7-ai" \
                    "FBtuFdSWNjZgvIkKxHHKGi0qMkUl4-JnpPHiJdnOTGeBhAPfMTJnYKfoKV14A4HC" \
                    "W0NcoFYenTxnvHV-A6bTZ6iFAmTyUp0SicOSEY3Hiov1OMppBpLkDuHe2TtpdK_c" \
                    "JLLerCVjYnN8DRqTpdmfsAkdonRseXyhRhwO6yFwVy9TEc9_OFuqGMOsy5_VIts6" \
                    "pG0saJJUQlOuLTxHwtPdloqjI8l3yMiDfXvJF2_epb_PYpKkAQZy_UWM5u4P_pnb" \
                    "UdImyYo6HBmnq-qO07J7b3yOSAzWhklBD7cMh1ucSOyF9-u03mLOfx2-SXq4tIuU" \
                    "Lz3RHZECgYEA0Rj-ipCKEPwQORViDFYYk1txzFSVKVX9Q-ozl6i93kTXx8GF7vkX" \
                    "L6SaEbKDA2EARuczr1gjymlvgRAwbsX7bDylSF6EsmPZ-EccNe4GoXmfbgMFDqGr" \
                    "3jVUmwEYwkte6EvP2Ha2GDwIuXFhcXWxgbbQxGGEcS5niei1mV0jv-sCgYEAzwv9" \
                    "BIYkeBC6_kejD2VwNzC1Jl97vg2It2URTZUGPFvcXh1Ed_i1itXwJ7wBjyBdwLJM" \
                    "IWjZcAYKET9NdBps2loATbOHrw4zFEqjKr_X-xSVU4bunipoY40fhl6a15ngUZ49" \
                    "3OJe_YtXEBHTVHorltIYuugu0zKk6uKbU_bt770CgYAR8_5u8UgZezr9W7umaYIE" \
                    "rPZRX_XKrcpoGWTCocdjnS-VxCT2xsZZ3d0opdYf5SU78T_7zyqLh4_-WeB-slsL" \
                    "CQ3777mfA3nEmn5ulvhUxveMX5AAmJsEIjoYcPiqPgRxF4lKAa9S11y8Z2LBdiR-" \
                    "ia7VHbZcbWqQab2l5FxcbwKBgCz_Ov7XtGdPo4QNx5daAVhNQqFTUQ5N3K-WzHri" \
                    "71cA09S0YaP9Ll88_ZN1HZWggB-X4EnGgrMA7QEwk8Gu2Idf1f8NDGj0Gg_H5Mwu" \
                    "o17S610azxMavlMcYYSPXPGMZJ74WBOAMwrBVKuOZDJQ1tZRVMSSH1MRB5xwoTdP" \
                    "TAi1AoGAXqJUfDAjtLR0wFoLlV0GWGOObKkPZFCbFdv0_CY2dk0nKnSsYRCogiFP" \
                    "t9XhZG5kawEtdfqiNBDyeNVLu6FaZnRkid_tUqMKfCYLjNDq31OD1Pwvyuh6Hs1P" \
                    "hL2-nt6t9b7JMyzKjWq_OPuTPH0QErL3oiFbTaZ4fDXplH_6Snw"
