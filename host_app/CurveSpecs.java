package host;

/* Copyright (c) 2013 Yubico AB 
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */


import java.lang.reflect.Array;
import java.math.BigInteger;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECField;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.util.Arrays;


public class CurveSpecs {

	public final static byte[] p = { // 32 bytes
	(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
			(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
			(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
			(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
			(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
			(byte) 0xff, (byte) 0xff, (byte) 0xfe, (byte) 0xff, (byte) 0xff,
			(byte) 0xfc, (byte) 0x2f };

	public final static byte[] a = { // 32 bytes
	(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
			(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
			(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
			(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
			(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
			(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
			(byte) 0x00, (byte) 0x00 };

	public final static byte[] b = { // 32 bytes
	(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
			(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
			(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
			(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
			(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
			(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
			(byte) 0x00, (byte) 0x07 };

	// base point
	public final static byte[] G = { // 65 bytes
			(byte) 0x04, (byte) 0x79, (byte) 0xbe, (byte) 0x66, (byte) 0x7e,
			(byte) 0xf9, (byte) 0xdc, (byte) 0xbb, (byte) 0xac, (byte) 0x55,
			(byte) 0xa0, (byte) 0x62, (byte) 0x95, (byte) 0xce, (byte) 0x87,
			(byte) 0x0b, (byte) 0x07, (byte) 0x02, (byte) 0x9b, (byte) 0xfc,
			(byte) 0xdb, (byte) 0x2d, (byte) 0xce, (byte) 0x28, (byte) 0xd9,
			(byte) 0x59, (byte) 0xf2, (byte) 0x81, (byte) 0x5b, (byte) 0x16,
			(byte) 0xf8, (byte) 0x17, (byte) 0x98, (byte) 0x48, (byte) 0x3a,
			(byte) 0xda, (byte) 0x77, (byte) 0x26, (byte) 0xa3, (byte) 0xc4,
			(byte) 0x65, (byte) 0x5d, (byte) 0xa4, (byte) 0xfb, (byte) 0xfc,
			(byte) 0x0e, (byte) 0x11, (byte) 0x08, (byte) 0xa8, (byte) 0xfd,
			(byte) 0x17, (byte) 0xb4, (byte) 0x48, (byte) 0xa6, (byte) 0x85,
			(byte) 0x54, (byte) 0x19, (byte) 0x9c, (byte) 0x47, (byte) 0xd0,
			(byte) 0x8f, (byte) 0xfb, (byte) 0x10, (byte) 0xd4, (byte) 0xb8 };

	// order
	public final static byte[] r = { // 32 bytes
	(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
			(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
			(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
			(byte) 0xfe, (byte) 0xba, (byte) 0xae, (byte) 0xdc, (byte) 0xe6,
			(byte) 0xaf, (byte) 0x48, (byte) 0xa0, (byte) 0x3b, (byte) 0xbf,
			(byte) 0xd2, (byte) 0x5e, (byte) 0x8c, (byte) 0xd0, (byte) 0x36,
			(byte) 0x41, (byte) 0x41 };

	// cofactor
	public final static short h = 0x01;

	/*
	static public KeyPair newKeyPair() {
		KeyPair kp = new KeyPair(KeyPair.ALG_EC_FP, (short) 256);

		ECPrivateKey ecPrv = (ECPrivateKey) kp.getPrivate();
		ECPublicKey ecPub = (ECPublicKey) kp.getPublic();

		ecPrv.setFieldFP(p, (short) 0, (short) p.length);
		ecPrv.setA(a, (short) 0, (short) a.length);
		ecPrv.setB(b, (short) 0, (short) b.length);
		ecPrv.setG(G, (short) 0, (short) G.length);
		ecPrv.setR(r, (short) 0, (short) r.length);
		ecPrv.setK(h)

		ecPub.setFieldFP(p, (short) 0, (short) p.length);
		ecPub.setA(a, (short) 0, (short) a.length);
		ecPub.setB(b, (short) 0, (short) b.length);
		ecPub.setG(G, (short) 0, (short) G.length);
		ecPub.setR(r, (short) 0, (short) r.length);
		ecPub.setK(h)

		return kp;
	}*/

	/*
	static public AlgorithmParameterSpec getSpec() {
		BigInteger bi_p = new BigInteger(1, p);
		BigInteger bi_a = new BigInteger(1, a);
		BigInteger bi_b = new BigInteger(1, b);

		EllipticCurve ecc = new EllipticCurve(new ECFieldFp(bi_p), bi_a, bi_b);

		if (G.length % 2 == 0 || G[0] != 0x04) {
			throw new IllegalArgumentException("Only uncompressed from of generator supported");
		}

		int coor_len = (G.length - 1) / 2;

		byte[] arr_x = Arrays.copyOfRange(G, 1, coor_len + 1);
		BigInteger G_x = new BigInteger(1, arr_x);
		if (arr_x.length != 32) {
			throw new IllegalArgumentException("wrong length");
		}

		byte[] arr_y = Arrays.copyOfRange(G, coor_len + 1, G.length);
		if (arr_y.length != 32) {
			throw new IllegalArgumentException("wrong length: " + arr_y.length + " tot: " + G.length + " f " + arr_y[0]);
		}

		BigInteger G_y = new BigInteger(1, arr_y);
		ECPoint point_G = new ECPoint(G_x, G_y);

		BigInteger bi_r = new BigInteger(1, r);

		return new ECParameterSpec(ecc, point_G, bi_r, h);
	}*/

	public static final ECParameterSpec EC_P256_PARAMS = initECParams(
			"FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
			"FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC",
			"5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B",
			"6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
			"4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
			"FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
			1
	);

	public static final ECParameterSpec EC_P256K_PARAMS = initECParams(
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",
			"0000000000000000000000000000000000000000000000000000000000000000",
			"0000000000000000000000000000000000000000000000000000000000000007",
			"79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
			"483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8",
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
			1
	);

	public static final ECParameterSpec EC_BRAINPOOL_P320_R1_PARAMS = initECParams(
			"D35E472036BC4FB7E13C785ED201E065F98FCFA6F6F40DEF4F92B9EC7893EC28FCD412B1F1B32E27",
			"3EE30B568FBAB0F883CCEBD46D3F3BB8A2A73513F5EB79DA66190EB085FFA9F492F375A97D860EB4",
			"520883949DFDBC42D3AD198640688A6FE13F41349554B49ACC31DCCD884539816F5EB4AC8FB1F1A6",
			"43BD7E9AFB53D8B85289BCC48EE5BFE6F20137D10A087EB6E7871E2A10A599C710AF8D0D39E20611",
			"14FDD05545EC1CC8AB4093247F77275E0743FFED117182EAA9C77877AAAC6AC7D35245D1692E8EE1",
			"D35E472036BC4FB7E13C785ED201E065F98FCFA5B68F12A32D482EC7EE8658E98691555B44C59311",
			1
	);
	public static final ECParameterSpec EC_BRAINPOOL_P256_R1_PARAMS = initECParams(
			"a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377",
			"7d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9",
			"26dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b6",
			"8bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262",
			"547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997",
			"a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7",
			1
	);

	private static ECParameterSpec initECParams(
			String sfield, String a, String b, String gx, String gy,
			String n, int h) {

		ECField field = new ECFieldFp(bigInt(sfield));
		EllipticCurve curve = new EllipticCurve(field,
				bigInt(a), bigInt(b));
		ECPoint g = new ECPoint(bigInt(gx), bigInt(gy));
		return new ECParameterSpec(curve, g, bigInt(n), h);
	}

	private static BigInteger bigInt(String s) {
		return new BigInteger(s, 16);
	}
}
