import java.math.BigInteger;

/**
 * Object representing a curve point on a Edwards curve.
 * @author Steven Tieu
 * @version 05-27-2024
 */
public class Edwards448Point {
    private BigInteger x;
    private BigInteger y;

    public Edwards448Point() {
        this(BigInteger.ZERO, BigInteger.ONE);
    }

    /**
     * Creates a Edwards point at coordinates x and y. It is assumed that
     * these coordinates lie on the curve x^2 + y^2 = 1 + d(x^2)(y^2),
     * 
     * @param x is the x-coordinate of the point.
     * @param y is the y-coordinate of the point.
     */
    public Edwards448Point(BigInteger x, BigInteger y) {
        this.x = x;
        this.y = y;
    }

    public Edwards448Point(boolean xLsb, BigInteger y, BigInteger d, BigInteger p) {
        BigInteger denom = y.pow(2);
        denom = denom.multiply(d.negate());
        denom = denom.add(BigInteger.ONE);
    
        BigInteger x2 = (BigInteger.ONE).subtract(y.pow(2));
        x2 = x2.multiply(denom.modInverse(p));

        this.x = sqrt(x2, p, xLsb);
        this.y = y;
    }

    /**
     * Gets the x-coordinate of this point.
     * 
     * @return the x-coordinate.
     */
    public BigInteger getX() {
        return this.x;
    }

    /**
     * Gets the y-coordinate of this point.
     * 
     * @return the y-coordinate.
     */
    public BigInteger getY() {
        return this.y;
    }

    /**
     * Adds two Edwards points using Edwards point addition formula.
     * modulo operation performed on final sum with modulus p.
     * 
     * @param other is the other Edwards point to sum with this point.
     * @return the sum of this Edwards point and the other.
     */
    public Edwards448Point add(Edwards448Point other, BigInteger d, BigInteger p) {
        BigInteger xNumer = x.multiply(other.getY());
        xNumer = xNumer.add(y.multiply(other.getX()));

        BigInteger yNumer = y.multiply(other.getY());
        yNumer = yNumer.subtract(x.multiply(other.getX()));

        BigInteger xDenom = d.multiply(x);
        xDenom = xDenom.multiply(other.getX());
        xDenom = xDenom.multiply(y);
        xDenom = xDenom.multiply(other.getY());

        BigInteger yDenom = (BigInteger.ONE).subtract(xDenom);
        xDenom = xDenom.add(BigInteger.ONE);

        BigInteger sumX = xNumer.multiply(xDenom.modInverse(p));
        BigInteger sumY = yNumer.multiply(yDenom.modInverse(p));

        return new Edwards448Point(sumX.mod(p), sumY.mod(p));
    }

    /**
     * Multiply a scalar on this point.
     * 
     * @param scalar is the scalar to multiply with.
     * @return the product of multiplying this Edwards point by the scalar.
     */
    public Edwards448Point multiply(BigInteger scalar, BigInteger d, BigInteger p) {
        Edwards448Point V = new Edwards448Point();
        if(scalar.compareTo(BigInteger.ZERO) != 0) {
            String bitStr = scalar.toString(2);
            V = new Edwards448Point(x, y);
            for(int i = bitStr.length() - 1; i >= 0; i--) {
                V = V.add(V, d, p);
                if(bitStr.charAt(i) == '1') {
                    V = V.add(this, d, p);
                } 
            }
        }
        return V;
    }

    /**
     * Gets the opposite of this Edwards point.
     * 
     * @return the opposite of this Edwards point.
     */
    public Edwards448Point getOpposite() {
        return new Edwards448Point(x.negate(), y);
    }

    /**
     * Compute a square root of v mod p with a specified least-significant bit
     * if such a root exists.
     *
     * @author Paulo Barreto
     * This implementation is provided by Professor Paulo Barreto, who
     * is teaching the course for this project.
     *
     * @param v the radicand.
     * @param p the modulus (must satisfy p mod 4 = 3).
     * @param lsb desired least significant bit (true: 1, false: 0).
     * @return a square root r of v mod p with r mod 2 = 1 iff lsb = true
     * if such a root exists, otherwise null.
     */
    private BigInteger sqrt(BigInteger v, BigInteger p, boolean lsb) {
        assert (p.testBit(0) && p.testBit(1)); // p = 3 (mod 4)
        if (v.signum() == 0) {
            return BigInteger.ZERO;
        }
        BigInteger r = v.modPow(p.shiftRight(2).add(BigInteger.ONE), p);
        if (r.testBit(0) != lsb) {
            r = p.subtract(r); // correct the lsb
        }
        return (r.multiply(r).subtract(v).mod(p).signum() == 0) ? r : null;
    }

    @Override
    public String toString() {
        return "X is: " + x.toString(10) + " and Y is " + y.toString(10);
    }

}
