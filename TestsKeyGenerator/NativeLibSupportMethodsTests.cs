using KeyGenNameSpace;
using NUnit.Framework;
using System.Numerics;

namespace TestsKeyGenerator {
    public class NativeLibSupportMethodsTests {

        [Test]
        public void ModInverse() {
            BigInteger input1 = BigInteger.Parse("65341020041517633956166170261014086368942546761318486551877808671514674964848");
            BigInteger primeModulus = BigInteger.Parse("115792089237316195423570985008687907853269984665640564039457584007908834671663");
            BigInteger target = BigInteger.Parse("83174505189910067536517124096019359197644205712500122884473429251812128958118");

            var result = MySec256.modInverse(input1, primeModulus);

            Assert.AreEqual(target, result);
        }

        [Test]
        public void ModInverse_1() {
            BigInteger input1 = BigInteger.Parse("13");
            BigInteger primeModulus = BigInteger.Parse("47");
            BigInteger target = BigInteger.Parse("29");

            var result = MySec256.modInverse(input1, primeModulus);

            Assert.AreEqual(target, result);
        }
        [Test]
        public void ModInverse_2() {
            BigInteger input1 = BigInteger.Parse("-21764953028825590619267164199465005895889343650340124505909980191288355451828");
            BigInteger primeModulus = BigInteger.Parse("115792089237316195423570985008687907853269984665640564039457584007908834671663");
            BigInteger target = BigInteger.Parse("-10464606811927168450269177742698359003875668665547057887775726258014988875902");

            var result = MySec256.modInverse(input1, primeModulus);

            Assert.AreEqual(target, result);
        }

        [Test]
        public void MyModulus() {
            BigInteger input1 = BigInteger.Parse("756628490253123014067933708583503295844929075882239485540431356534910033618830501144105195285364489562157441837796863614070956636498456792910898817389940831543204657474297072356228690296487944931559885281889207062770782744748470400");
            BigInteger input2 = BigInteger.Parse("115792089237316195423570985008687907853269984665640564039457584007908834671663");
            BigInteger target = BigInteger.Parse("91914383230618135761690975197207778399550061809281766160147273830617914855857");

            var result = MySec256.MyModulus(input1, input2);

            Assert.AreEqual(target, result);
        }
        [Test]
        public void Double() {
            BigInteger input1 = BigInteger.Parse("55066263022277343669578718895168534326250603453777594175500187360389116729240");
            BigInteger input2 = BigInteger.Parse("32670510020758816978083085130507043184471273380659243275938904335757337482424");
            var point = new Tuple<BigInteger, BigInteger>(input1, input2);
            BigInteger target1 = BigInteger.Parse("89565891926547004231252920425935692360644145829622209833684329913297188986597");
            BigInteger target2 = BigInteger.Parse("12158399299693830322967808612713398636155367887041628176798871954788371653930");

            var targetPoint = new Tuple<BigInteger, BigInteger>(target1, target2);
            var result = MySec256.Double(point);

            Assert.AreEqual(targetPoint, result);
        }
        [Test]
        public void Add() {
            BigInteger input1 = BigInteger.Parse("89565891926547004231252920425935692360644145829622209833684329913297188986597");
            BigInteger input11 = BigInteger.Parse("12158399299693830322967808612713398636155367887041628176798871954788371653930");
            BigInteger input2 = BigInteger.Parse("55066263022277343669578718895168534326250603453777594175500187360389116729240");
            BigInteger input21 = BigInteger.Parse("32670510020758816978083085130507043184471273380659243275938904335757337482424");
            var point1 = new Tuple<BigInteger, BigInteger>(input1, input11);
            var point2 = new Tuple<BigInteger, BigInteger>(input2, input21);
            BigInteger target1 = BigInteger.Parse("112711660439710606056748659173929673102114977341539408544630613555209775888121");
            BigInteger target2 = BigInteger.Parse("25583027980570883691656905877401976406448868254816295069919888960541586679410");

            var targetPoint = new Tuple<BigInteger, BigInteger>(target1, target2);
            var result = MySec256.Add(point1, point2);

            Assert.AreEqual(targetPoint, result);
        }


        [Test]
        public void Add_1() {
            BigInteger input1 = BigInteger.Parse("33301309993451753050311554695703528430361259803437469669590207169100761277412");
            BigInteger input11 = BigInteger.Parse("91711666877231500617203373035680263572492971120307578300405368749466283229019");
            BigInteger inputG = BigInteger.Parse("55066263022277343669578718895168534326250603453777594175500187360389116729240");
            BigInteger inputG1 = BigInteger.Parse("32670510020758816978083085130507043184471273380659243275938904335757337482424");
            var point1 = new Tuple<BigInteger, BigInteger>(input1, input11);
            var pointG = new Tuple<BigInteger, BigInteger>(inputG, inputG1);
            BigInteger target1 = BigInteger.Parse("97505755694356382817881959832717013755620551362654128955029190924747025549326");
            BigInteger target2 = BigInteger.Parse("39856815248295663243990443767776362321337592747889787217974905533720651000664");

            var targetPoint = new Tuple<BigInteger, BigInteger>(target1, target2);
            var result = MySec256.Add(point1, pointG);

            Assert.AreEqual(targetPoint, result);
        }

        [Test]
        public void Add_2() {
            BigInteger input1 = BigInteger.Parse("89565891926547004231252920425935692360644145829622209833684329913297188986597");
            BigInteger input11 = BigInteger.Parse("12158399299693830322967808612713398636155367887041628176798871954788371653930");
            BigInteger inputG = BigInteger.Parse("55066263022277343669578718895168534326250603453777594175500187360389116729240");
            BigInteger inputG1 = BigInteger.Parse("32670510020758816978083085130507043184471273380659243275938904335757337482424");
            var point1 = new Tuple<BigInteger, BigInteger>(input1, input11);
            var pointG = new Tuple<BigInteger, BigInteger>(inputG, inputG1);
            BigInteger target1 = BigInteger.Parse("112711660439710606056748659173929673102114977341539408544630613555209775888121");
            BigInteger target2 = BigInteger.Parse("25583027980570883691656905877401976406448868254816295069919888960541586679410");

            var targetPoint = new Tuple<BigInteger, BigInteger>(target1, target2);
            var result = MySec256.Add(point1, pointG);

            Assert.AreEqual(targetPoint, result);
        }
        [Test]
        public void Multiply() {
            BigInteger input1 = BigInteger.Parse("3");
            var point1 = new Tuple<BigInteger, BigInteger>(BigInteger.Parse("55066263022277343669578718895168534326250603453777594175500187360389116729240"), BigInteger.Parse("32670510020758816978083085130507043184471273380659243275938904335757337482424"));
            BigInteger target1 = BigInteger.Parse("112711660439710606056748659173929673102114977341539408544630613555209775888121");
            BigInteger target2 = BigInteger.Parse("25583027980570883691656905877401976406448868254816295069919888960541586679410");

            var targetPoint = new Tuple<BigInteger, BigInteger>(target1, target2);
            var result = MySec256.Multiply(input1, point1);

            Assert.AreEqual(targetPoint, result);
        }

        [Test]
        public void Multiply2() {
            BigInteger input1 = BigInteger.Parse("11");
            var point1 = new Tuple<BigInteger, BigInteger>(BigInteger.Parse("55066263022277343669578718895168534326250603453777594175500187360389116729240"), BigInteger.Parse("32670510020758816978083085130507043184471273380659243275938904335757337482424"));
            BigInteger target1 = BigInteger.Parse("53957576663012291606402345341061437133522758407718089353314528343643821967563");
            BigInteger target2 = BigInteger.Parse("98386217607324929854432842186271083758341411730506808463586570492533445740059");

            var targetPoint = new Tuple<BigInteger, BigInteger>(target1, target2);
            var result = MySec256.Multiply(input1, point1);

            Assert.AreEqual(targetPoint, result);
        }
    }
}
