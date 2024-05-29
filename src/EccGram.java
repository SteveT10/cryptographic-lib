public class EccGram {
    Ed448pt Z;
    byte[] c;
    byte[] t;

    EccGram(Ed448pt Z, byte[] c, byte[] t) {
        this.Z = new Ed448pt(Z.getX(), Z.getY());
        this.c = c.clone();
        this.t = t.clone();
    }

    public Ed448pt getZ() {
        return new Ed448pt(Z.getX(), Z.getY());
    }

    public byte[] getC() {
        return c.clone();
    }

    public byte[] getT() {
        return t.clone();
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("Z: ");
        sb.append(Z);
        sb.append("\n");
        sb.append("c: ");
        for(int i = 0; i < c.length; i++) {
            sb.append(c[i] & 0Xff);
        }
        sb.append("\n");
        sb.append("t: ");
        for(int i = 0; i < t.length; i++) {
            sb.append(t[i] & 0Xff);
        }
        return sb.toString();
    }
}
