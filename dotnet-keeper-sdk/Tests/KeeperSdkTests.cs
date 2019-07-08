using System;
using System.Security.Cryptography;
using KeeperSecurity.Sdk;
using Xunit;

namespace Tests
{
 
    public class ConfigurationTest
    {
        [Fact]
        public void TestAesGcmEncryption()
        {
            var key = "c-EeCGlAO7F9QoJThlFBrhSCLYMe1H6GtKP-rezDnik".Base64UrlDecode();
            var nonce = "Nt9_Y37C_43eRCRQ".Base64UrlDecode();
            var data = ("nm-8mRG7xYwUG2duaOZzw-ttuqfetWjVIzoridJF0EJOGlDLs1ZWQ7F9mOJ0Hxu" +
                "ydFyojxdxVo1fGwbfwf0Jew07HhGGE5UZ_s57rQvhizDW3F3z9a7EqHRon0EilC" +
                "bMhIzE").Base64UrlDecode();

            var expectedResult = ("Nt9_Y37C_43eRCRQCptb64zFaJVLcXF1udabOr_fyGXkpjpYeCAI7zVQD4JjewB" +
                "CP1Xp7D6dx-pxdRWkhDEnVhJ3fzezi8atmmzvf2ICfkDK0IHHB8iNSx_R1Ru8To" +
                "zb-IdavT3wKi7nKSJLDdt-dk-Mw7bCewpZtg4wY-1UQw").Base64UrlDecode();

            var result = CryptoUtils.EncryptAesV2(data, key, nonce);
            Assert.Equal(expectedResult, result);

            var originalData = CryptoUtils.DecryptAesV2(expectedResult, key);
            Assert.Equal(originalData, data);
        }

        [Fact]
        public void TestKeyDerivationV2()
        {
            var password = "q2rXmNBFeLwAEX55hVVTfg";
            var domain = "1oZZl0fKjU4";
            var salt = "Ozv5_XSBgw-XSrDosp8Y1A".Base64UrlDecode();
            var expectedKey = "rXE9OHv_gcvUHdWuBIkyLsRDXT1oddQCzf6PrIECl2g".Base64UrlDecode();

            var key = CryptoUtils.DeriveKeyV2(domain, password, salt, 1000);
            Assert.Equal(expectedKey, key);
        }
    }
}