import io
from unittest import TestCase

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
