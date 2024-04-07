using NUnit.Framework;

namespace TestsKeyGenerator {
    [TestFixture]
    public class HashConverterTest {
        [Test]
        public void Test() {
            var input = "11F53BE6DC18F1DD5DC9F111D83EB93F0F9B09BDA1812B000000000000000000";
            var res = "test1";
            Assert.AreEqual("0000000000000000002b81a1bd099b0f3fb93ed811f1c95dddf118dce63bf511", res);

        }
        [Test]
        public void Test2() {
            var input = "11F53BE6DC18F1DD5DC9F111D83EB93F0F9B09BDA1812B000000000000000000";
            var res = "test1";
            Assert.AreEqual("test1", res);

        }
    }
}
