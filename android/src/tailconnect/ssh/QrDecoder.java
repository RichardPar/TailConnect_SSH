package tailconnect.ssh;

import java.io.ByteArrayOutputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Finds and reads a QR code in a greyscale camera frame, with no libraries.
 * It uses no android.* classes, so it can be tested on a desktop JVM.
 *
 * <p>The steps: turn the frame black and white against the local average
 * brightness; find the three finder squares (their 1:1:3:1:1 stripes);
 * find the small alignment square near the fourth corner; map the code's
 * grid onto the picture (a perspective transform) and read each module;
 * read the format bits (error correction level and mask); unmask and read
 * the codewords; fix errors with Reed-Solomon; decode the text.
 */
final class QrDecoder {
    private QrDecoder() {}

    /**
     * The text of a QR code in the frame, or null if none could be read.
     * lum holds one byte of brightness per pixel, rows stride bytes apart.
     */
    static String decode(byte[] lum, int w, int h, int stride) {
        if (w < 21 || h < 21) return null;
        boolean[] black = binarize(lum, w, h, stride);
        List<Finder> found = findFinders(black, w, h);
        if (found.size() < 3) return null;
        // Try the likeliest few sets of three finder patterns.
        List<Finder[]> triples = bestTriples(found);
        for (Finder[] t : triples) {
            String s = decodeAt(black, w, h, t[0], t[1], t[2]);
            if (s != null) return s;
        }
        return null;
    }

    // ---- black and white ----

    /** Black where a pixel is darker than its neighbourhood's average. */
    static boolean[] binarize(byte[] lum, int w, int h, int stride) {
        int W = w + 1;
        int[] ii = new int[W * (h + 1)]; // integral image: sums of everything above and left
        for (int r = 0; r < h; r++) {
            int row = 0, base = r * stride, o = (r + 1) * W, p = r * W;
            for (int c = 0; c < w; c++) {
                row += lum[base + c] & 0xff;
                ii[o + c + 1] = ii[p + c + 1] + row;
            }
        }
        int rad = Math.max(8, Math.min(w, h) / 16);
        boolean[] out = new boolean[w * h];
        for (int r = 0; r < h; r++) {
            int y0 = Math.max(0, r - rad), y1 = Math.min(h, r + rad + 1);
            int base = r * stride;
            for (int c = 0; c < w; c++) {
                int x0 = Math.max(0, c - rad), x1 = Math.min(w, c + rad + 1);
                int sum = ii[y1 * W + x1] - ii[y0 * W + x1] - ii[y1 * W + x0] + ii[y0 * W + x0];
                int n = (y1 - y0) * (x1 - x0);
                // A little below the average, so flat areas stay white.
                out[r * w + c] = (lum[base + c] & 0xff) * n < sum - 6 * n;
            }
        }
        return out;
    }

    // ---- finder patterns ----

    static final class Finder {
        float x, y, ms; // centre, and module size in pixels
        int count;      // how many scans confirmed it
        Finder(float x, float y, float ms) { this.x = x; this.y = y; this.ms = ms; this.count = 1; }
    }

    private static List<Finder> findFinders(boolean[] b, int w, int h) {
        List<Finder> out = new ArrayList<>();
        int step = Math.max(1, h / 400);
        int[] sc = new int[5];
        for (int r = 0; r < h; r += step) {
            java.util.Arrays.fill(sc, 0);
            int st = 0;
            int row = r * w;
            for (int c = 0; c < w; c++) {
                if (b[row + c]) {
                    if ((st & 1) == 1) st++;
                    sc[st]++;
                } else if ((st & 1) == 0) {
                    if (st == 4) {
                        if (crossRatio(sc)) possibleCenter(b, w, h, sc, r, c, out);
                        sc[0] = sc[2]; sc[1] = sc[3]; sc[2] = sc[4]; sc[3] = 1; sc[4] = 0;
                        st = 3;
                    } else {
                        sc[++st]++;
                    }
                } else {
                    sc[st]++;
                }
            }
            if (st == 4 && crossRatio(sc)) possibleCenter(b, w, h, sc, r, w, out);
        }
        return out;
    }

    /** Whether runs look like a finder's 1:1:3:1:1 black-white stripes. */
    private static boolean crossRatio(int[] sc) {
        int total = 0;
        for (int v : sc) {
            if (v == 0) return false;
            total += v;
        }
        if (total < 7) return false;
        float ms = total / 7f, var = ms * 0.6f;
        return Math.abs(ms - sc[0]) < var && Math.abs(ms - sc[1]) < var
                && Math.abs(3 * ms - sc[2]) < 3 * var
                && Math.abs(ms - sc[3]) < var && Math.abs(ms - sc[4]) < var;
    }

    private static void possibleCenter(boolean[] b, int w, int h, int[] sc, int r, int end, List<Finder> out) {
        int total = sc[0] + sc[1] + sc[2] + sc[3] + sc[4];
        float cx = end - sc[4] - sc[3] - sc[2] / 2f;
        float cy = crossCheck(b, w, h, (int) cx, r, sc[2], total, false);
        if (Float.isNaN(cy)) return;
        cx = crossCheck(b, w, h, (int) cx, (int) cy, sc[2], total, true);
        if (Float.isNaN(cx)) return;
        float ms = total / 7f;
        for (Finder f : out) {
            if (Math.abs(f.x - cx) <= f.ms * 1.5f && Math.abs(f.y - cy) <= f.ms * 1.5f
                    && Math.abs(f.ms - ms) <= Math.max(1f, f.ms * 0.5f)) {
                int n = f.count;
                f.x = (f.x * n + cx) / (n + 1);
                f.y = (f.y * n + cy) / (n + 1);
                f.ms = (f.ms * n + ms) / (n + 1);
                f.count++;
                return;
            }
        }
        out.add(new Finder(cx, cy, ms));
    }

    /**
     * Checks the stripes along a column (or row) through a possible centre;
     * returns the refined centre coordinate along it, or NaN.
     */
    private static float crossCheck(boolean[] b, int w, int h, int x, int y, int max, int origTotal, boolean horiz) {
        int lim = horiz ? w : h;
        int at = horiz ? x : y;
        if (at < 0 || at >= lim) return Float.NaN;
        int[] sc = new int[5];
        int i = at;
        while (i >= 0 && px(b, w, x, y, i, horiz)) { sc[2]++; i--; }
        if (i < 0) return Float.NaN;
        while (i >= 0 && !px(b, w, x, y, i, horiz) && sc[1] <= max) { sc[1]++; i--; }
        if (i < 0 || sc[1] > max) return Float.NaN;
        while (i >= 0 && px(b, w, x, y, i, horiz) && sc[0] <= max) { sc[0]++; i--; }
        if (sc[0] > max) return Float.NaN;
        i = at + 1;
        while (i < lim && px(b, w, x, y, i, horiz)) { sc[2]++; i++; }
        if (i == lim) return Float.NaN;
        while (i < lim && !px(b, w, x, y, i, horiz) && sc[3] <= max) { sc[3]++; i++; }
        if (i == lim || sc[3] > max) return Float.NaN;
        while (i < lim && px(b, w, x, y, i, horiz) && sc[4] <= max) { sc[4]++; i++; }
        if (sc[4] > max) return Float.NaN;
        int total = sc[0] + sc[1] + sc[2] + sc[3] + sc[4];
        if (5 * Math.abs(total - origTotal) >= 2 * origTotal) return Float.NaN;
        return crossRatio(sc) ? i - sc[4] - sc[3] - sc[2] / 2f : Float.NaN;
    }

    private static boolean px(boolean[] b, int w, int x, int y, int i, boolean horiz) {
        return horiz ? b[y * w + i] : b[i * w + x];
    }

    /**
     * Sets of three finders that could be one code's corners, best first:
     * a right-angled, isosceles triangle of similar-sized patterns. Each is
     * ordered bottom-left, top-left, top-right.
     */
    private static List<Finder[]> bestTriples(List<Finder> all) {
        List<Finder> fs = new ArrayList<>(all);
        fs.sort((a, c) -> c.count - a.count);
        int n = Math.min(fs.size(), 10);
        List<float[]> scored = new ArrayList<>(); // score, i, j, k
        for (int i = 0; i < n; i++)
            for (int j = i + 1; j < n; j++)
                for (int k = j + 1; k < n; k++) {
                    Finder a = fs.get(i), b = fs.get(j), c = fs.get(k);
                    float lo = Math.min(a.ms, Math.min(b.ms, c.ms)), hi = Math.max(a.ms, Math.max(b.ms, c.ms));
                    if (hi > lo * 2f) continue;
                    float[] d = {dist2(a, b), dist2(a, c), dist2(b, c)};
                    java.util.Arrays.sort(d);
                    float s1 = (float) Math.sqrt(d[0]), s2 = (float) Math.sqrt(d[1]);
                    float ms = (a.ms + b.ms + c.ms) / 3;
                    if (s1 < 10 * ms) continue; // corners at least 14 modules apart
                    float err = Math.abs(s2 - s1) / s2 + Math.abs(d[2] - (d[0] + d[1])) / d[2];
                    if (err > 0.6f) continue;
                    float score = err + (hi - lo) / hi * 0.5f - Math.min(a.count + b.count + c.count, 15) * 0.01f;
                    scored.add(new float[]{score, i, j, k});
                }
        scored.sort((p, q) -> Float.compare(p[0], q[0]));
        List<Finder[]> out = new ArrayList<>();
        for (int t = 0; t < Math.min(4, scored.size()); t++) {
            float[] s = scored.get(t);
            out.add(order(fs.get((int) s[1]), fs.get((int) s[2]), fs.get((int) s[3])));
        }
        return out;
    }

    private static float dist2(Finder a, Finder b) {
        float dx = a.x - b.x, dy = a.y - b.y;
        return dx * dx + dy * dy;
    }

    /** Orders three finders as bottom-left, top-left (the right angle), top-right. */
    private static Finder[] order(Finder p, Finder q, Finder r) {
        float pq = dist2(p, q), qr = dist2(q, r), pr = dist2(p, r);
        Finder a, b, c; // b is opposite the longest side
        if (qr >= pq && qr >= pr) { b = p; a = q; c = r; }
        else if (pr >= qr && pr >= pq) { b = q; a = p; c = r; }
        else { b = r; a = p; c = q; }
        if ((c.x - b.x) * (a.y - b.y) - (c.y - b.y) * (a.x - b.x) < 0) { Finder t = a; a = c; c = t; }
        return new Finder[]{a, b, c};
    }

    // ---- sampling the grid ----

    private static String decodeAt(boolean[] b, int w, int h, Finder bl, Finder tl, Finder tr) {
        // Module sizes measured along the code's own axes (a rotated code's
        // finders look wider along image rows than they are).
        float mx = (moduleAlong(b, w, h, tl, tr) + moduleAlong(b, w, h, tr, tl)) / 2;
        float my = (moduleAlong(b, w, h, tl, bl) + moduleAlong(b, w, h, bl, tl)) / 2;
        if (Float.isNaN(mx) || Float.isNaN(my)) return null;
        float d = ((float) Math.sqrt(dist2(tl, tr)) / mx + (float) Math.sqrt(dist2(tl, bl)) / my) / 2 + 7;
        int dim = Math.round((d - 17) / 4) * 4 + 17;
        int[] tries = {dim, dim - 4, dim + 4};
        for (int size : tries) {
            if (size < 21 || size > 177) continue;
            String s = decodeSize(b, w, h, bl, tl, tr, size);
            if (s != null) return s;
        }
        return null;
    }

    /**
     * A finder's module size along the line towards another finder: its
     * width (7 modules) across black, white, black-centre, white, black.
     */
    private static float moduleAlong(boolean[] b, int w, int h, Finder f, Finder to) {
        float dx = to.x - f.x, dy = to.y - f.y;
        float len = (float) Math.sqrt(dx * dx + dy * dy);
        if (len == 0) return Float.NaN;
        dx /= len;
        dy /= len;
        float a = toEdge(b, w, h, f, dx, dy), c = toEdge(b, w, h, f, -dx, -dy);
        if (Float.isNaN(a) || Float.isNaN(c)) return Float.NaN;
        return (a + c) / 7;
    }

    /** Distance from a finder's centre to its outer edge in one direction. */
    private static float toEdge(boolean[] b, int w, int h, Finder f, float dx, float dy) {
        int state = 0; // 0 centre black, 1 white ring, 2 black ring
        int max = Math.round(f.ms * 8);
        for (int t = 0; t <= max; t++) {
            int x = (int) (f.x + dx * t), y = (int) (f.y + dy * t);
            if (x < 0 || y < 0 || x >= w || y >= h) return state == 2 ? t : Float.NaN;
            boolean k = b[y * w + x];
            if (state == 0 && !k) state = 1;
            else if (state == 1 && k) state = 2;
            else if (state == 2 && !k) return t;
        }
        return Float.NaN;
    }

    private static String decodeSize(boolean[] b, int w, int h, Finder bl, Finder tl, Finder tr, int size) {
        int version = (size - 17) / 4;
        float brx = tr.x - tl.x + bl.x, bry = tr.y - tl.y + bl.y;
        double[] rough = homography(
                new double[]{3.5, 3.5, size - 3.5, 3.5, 3.5, size - 3.5, size - 3.5, size - 3.5},
                new double[]{tl.x, tl.y, tr.x, tr.y, bl.x, bl.y, brx, bry});
        if (rough == null) return null;
        double[] t = null;
        if (version >= 2) {
            float ms = (bl.ms + tl.ms + tr.ms) / 3;
            float[] ap = findAlignment(b, w, h, rough, size - 6.5, size - 6.5, Math.round(ms * 5));
            if (ap == null) ap = findAlignment(b, w, h, rough, size - 6.5, size - 6.5, Math.round(ms * 10));
            if (ap != null)
                t = homography(
                        new double[]{3.5, 3.5, size - 3.5, 3.5, 3.5, size - 3.5, size - 6.5, size - 6.5},
                        new double[]{tl.x, tl.y, tr.x, tr.y, bl.x, bl.y, ap[0], ap[1]});
        }
        if (t == null) t = rough;
        boolean[][] grid = new boolean[size][size];
        double[] p = new double[2];
        int outside = 0;
        for (int y = 0; y < size; y++)
            for (int x = 0; x < size; x++) {
                map(t, x + 0.5, y + 0.5, p);
                int ix = (int) Math.floor(p[0]), iy = (int) Math.floor(p[1]);
                if (ix < 0 || iy < 0 || ix >= w || iy >= h) { outside++; continue; }
                grid[y][x] = b[iy * w + ix];
            }
        if (outside > size * size / 10) return null;
        return readGrid(grid, version);
    }

    /**
     * Looks for the alignment pattern's centre near module (mx, my): the
     * spot where a 5×5 sample grid best matches its black-white-black rings.
     */
    private static float[] findAlignment(boolean[] b, int w, int h, double[] t, double mx, double my, int rad) {
        double[] c = new double[2], ex = new double[2], ey = new double[2];
        map(t, mx, my, c);
        map(t, mx + 1, my, ex);
        map(t, mx, my + 1, ey);
        double ux = ex[0] - c[0], uy = ex[1] - c[1], vx = ey[0] - c[0], vy = ey[1] - c[1];
        rad = Math.max(4, rad);
        int best = -1;
        double sx = 0, sy = 0;
        int n = 0;
        for (int dy = -rad; dy <= rad; dy++)
            for (int dx = -rad; dx <= rad; dx++) {
                double qx = c[0] + dx, qy = c[1] + dy;
                int score = 0;
                for (int j = -2; j <= 2; j++)
                    for (int i = -2; i <= 2; i++) {
                        int px = (int) Math.floor(qx + i * ux + j * vx), py = (int) Math.floor(qy + i * uy + j * vy);
                        boolean want = Math.max(Math.abs(i), Math.abs(j)) != 1;
                        boolean got = px >= 0 && py >= 0 && px < w && py < h && b[py * w + px];
                        if (want == got) score++;
                    }
                if (score > best) { best = score; sx = sy = 0; n = 0; }
                if (score == best) { sx += qx; sy += qy; n++; }
            }
        if (best < 23) return null;
        return new float[]{(float) (sx / n), (float) (sy / n)};
    }

    /** The perspective transform taking four src points to four dst points (x,y pairs). */
    static double[] homography(double[] src, double[] dst) {
        double[][] a = new double[8][9];
        for (int i = 0; i < 4; i++) {
            double x = src[2 * i], y = src[2 * i + 1], X = dst[2 * i], Y = dst[2 * i + 1];
            a[2 * i] = new double[]{x, y, 1, 0, 0, 0, -x * X, -y * X, X};
            a[2 * i + 1] = new double[]{0, 0, 0, x, y, 1, -x * Y, -y * Y, Y};
        }
        for (int col = 0; col < 8; col++) {
            int piv = col;
            for (int r = col + 1; r < 8; r++) if (Math.abs(a[r][col]) > Math.abs(a[piv][col])) piv = r;
            if (Math.abs(a[piv][col]) < 1e-12) return null;
            double[] tmp = a[col]; a[col] = a[piv]; a[piv] = tmp;
            for (int r = 0; r < 8; r++) {
                if (r == col) continue;
                double f = a[r][col] / a[col][col];
                if (f == 0) continue;
                for (int k = col; k < 9; k++) a[r][k] -= f * a[col][k];
            }
        }
        double[] m = new double[9];
        for (int i = 0; i < 8; i++) m[i] = a[i][8] / a[i][i];
        m[8] = 1;
        return m;
    }

    private static void map(double[] m, double x, double y, double[] out) {
        double d = m[6] * x + m[7] * y + m[8];
        out[0] = (m[0] * x + m[1] * y + m[2]) / d;
        out[1] = (m[3] * x + m[4] * y + m[5]) / d;
    }

    // ---- reading the grid ----

    // Error correction codewords per block and number of blocks, by level
    // (L, M, Q, H) and version (index 0 unused).
    private static final int[][] ECC_PER_BLOCK = {
        {-1, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30},
        {-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28},
        {-1, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26, 30, 28, 30, 30, 30, 30, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30},
        {-1, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26, 28, 30, 24, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30},
    };
    private static final int[][] NUM_BLOCKS = {
        {-1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25},
        {-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49},
        {-1, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8, 8, 10, 12, 16, 12, 17, 16, 18, 21, 20, 23, 23, 25, 27, 29, 34, 34, 35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62, 65, 68},
        {-1, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25, 25, 34, 30, 32, 35, 37, 40, 42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74, 77, 81},
    };

    static int formatBits(int data) {
        int rem = data;
        for (int i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
        return (data << 10 | rem) ^ 0x5412;
    }

    static int versionBits(int version) {
        int rem = version;
        for (int i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1F25);
        return version << 12 | rem;
    }

    static int[] alignmentPositions(int ver) {
        if (ver == 1) return new int[0];
        int size = ver * 4 + 17;
        int num = ver / 7 + 2;
        int step = ver == 32 ? 26 : (ver * 4 + num * 2 + 1) / (num * 2 - 2) * 2;
        int[] r = new int[num];
        r[0] = 6;
        for (int i = num - 1, pos = size - 7; i >= 1; i--, pos -= step) r[i] = pos;
        return r;
    }

    static int rawDataModules(int ver) {
        int r = (16 * ver + 128) * ver + 64;
        if (ver >= 2) {
            int num = ver / 7 + 2;
            r -= (25 * num - 10) * num - 55;
            if (ver >= 7) r -= 36;
        }
        return r;
    }

    private static String readGrid(boolean[][] g, int ver) {
        int size = g.length;
        // Format bits: two copies, each read bit 0 first (as they're drawn).
        int f1 = 0, f2 = 0;
        for (int i = 0; i <= 5; i++) f1 |= bit(g, 8, i) << i;
        f1 |= bit(g, 8, 7) << 6;
        f1 |= bit(g, 8, 8) << 7;
        f1 |= bit(g, 7, 8) << 8;
        for (int i = 9; i < 15; i++) f1 |= bit(g, 14 - i, 8) << i;
        for (int i = 0; i < 8; i++) f2 |= bit(g, size - 1 - i, 8) << i;
        for (int i = 8; i < 15; i++) f2 |= bit(g, 8, size - 15 + i) << i;
        int fmt = -1, bestD = 4;
        for (int data = 0; data < 32; data++) {
            int code = formatBits(data);
            int dd = Math.min(Integer.bitCount(code ^ f1), Integer.bitCount(code ^ f2));
            if (dd < bestD) { bestD = dd; fmt = data; }
        }
        if (fmt < 0) return null;
        int ecl = new int[]{1, 0, 3, 2}[fmt >> 3]; // format bits M=0 L=1 H=2 Q=3 → index L,M,Q,H
        int mask = fmt & 7;

        if (ver >= 7) {
            int v1 = 0, v2 = 0;
            for (int i = 0; i < 18; i++) {
                int a = size - 11 + i % 3, bb = i / 3;
                v1 |= bit(g, a, bb) << i;
                v2 |= bit(g, bb, a) << i;
            }
            int bestV = -1;
            bestD = 4;
            for (int v = 7; v <= 40; v++) {
                int code = versionBits(v);
                int dd = Math.min(Integer.bitCount(code ^ v1), Integer.bitCount(code ^ v2));
                if (dd < bestD) { bestD = dd; bestV = v; }
            }
            if (bestV >= 0 && bestV != ver) return null; // wrong size guessed
        }

        boolean[][] fn = functionModules(ver);
        int raw = rawDataModules(ver) / 8;
        byte[] cw = new byte[raw];
        int i = 0;
        for (int right = size - 1; right >= 1; right -= 2) {
            if (right == 6) right = 5;
            for (int vert = 0; vert < size; vert++)
                for (int j = 0; j < 2; j++) {
                    int x = right - j;
                    boolean up = ((right + 1) & 2) == 0;
                    int y = up ? size - 1 - vert : vert;
                    if (fn[y][x] || i >= raw * 8) continue;
                    boolean v = g[y][x] ^ masked(mask, x, y);
                    if (v) cw[i >>> 3] |= (byte) (0x80 >>> (i & 7));
                    i++;
                }
        }

        // Undo the interleaving into blocks, then correct each block.
        int numBlocks = NUM_BLOCKS[ecl][ver], ecc = ECC_PER_BLOCK[ecl][ver];
        int numShort = numBlocks - raw % numBlocks, shortLen = raw / numBlocks;
        int[][] blocks = new int[numBlocks][shortLen + 1];
        int k = 0;
        for (int col = 0; col <= shortLen; col++)
            for (int blk = 0; blk < numBlocks; blk++)
                if (col != shortLen - ecc || blk >= numShort) blocks[blk][col] = cw[k++] & 0xff;
        ByteArrayOutputStream data = new ByteArrayOutputStream();
        for (int blk = 0; blk < numBlocks; blk++) {
            int[] full = blocks[blk];
            int[] block;
            if (blk < numShort) { // drop the padding slot
                block = new int[shortLen];
                int dataLen = shortLen - ecc;
                System.arraycopy(full, 0, block, 0, dataLen);
                System.arraycopy(full, dataLen + 1, block, dataLen, ecc);
            } else {
                block = full;
            }
            if (!ReedSolomon.correct(block, ecc)) return null;
            for (int d = 0; d < block.length - ecc; d++) data.write(block[d]);
        }
        return decodeData(data.toByteArray(), ver);
    }

    private static int bit(boolean[][] g, int x, int y) {
        return g[y][x] ? 1 : 0;
    }

    private static boolean masked(int mask, int x, int y) {
        switch (mask) {
            case 0: return (x + y) % 2 == 0;
            case 1: return y % 2 == 0;
            case 2: return x % 3 == 0;
            case 3: return (x + y) % 3 == 0;
            case 4: return (x / 3 + y / 2) % 2 == 0;
            case 5: return x * y % 2 + x * y % 3 == 0;
            case 6: return (x * y % 2 + x * y % 3) % 2 == 0;
            default: return ((x + y) % 2 + x * y % 3) % 2 == 0;
        }
    }

    /** Which modules are fixed patterns rather than data, as [y][x]. */
    static boolean[][] functionModules(int ver) {
        int size = ver * 4 + 17;
        boolean[][] f = new boolean[size][size];
        for (int i = 0; i < size; i++) { f[6][i] = true; f[i][6] = true; }
        fill(f, 0, 0, 9, 9);
        fill(f, size - 8, 0, 8, 9);
        fill(f, 0, size - 8, 9, 8);
        int[] ap = alignmentPositions(ver);
        int n = ap.length;
        for (int i = 0; i < n; i++)
            for (int j = 0; j < n; j++) {
                if ((i == 0 && j == 0) || (i == 0 && j == n - 1) || (i == n - 1 && j == 0)) continue;
                fill(f, ap[i] - 2, ap[j] - 2, 5, 5);
            }
        if (ver >= 7) {
            fill(f, size - 11, 0, 3, 6);
            fill(f, 0, size - 11, 6, 3);
        }
        return f;
    }

    private static void fill(boolean[][] f, int x, int y, int w, int h) {
        for (int dy = 0; dy < h; dy++)
            for (int dx = 0; dx < w; dx++) f[y + dy][x + dx] = true;
    }

    // ---- the data ----

    private static final String ALNUM = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";

    private static String decodeData(byte[] d, int ver) {
        Bits in = new Bits(d);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int sizeClass = ver <= 9 ? 0 : ver <= 26 ? 1 : 2;
        while (in.left() >= 4) {
            int mode = in.read(4);
            if (mode == 0) break;
            switch (mode) {
                case 1: { // numeric
                    int n = in.read(new int[]{10, 12, 14}[sizeClass]);
                    while (n >= 3) { appendNum(out, in.read(10), 3); n -= 3; }
                    if (n == 2) appendNum(out, in.read(7), 2);
                    else if (n == 1) appendNum(out, in.read(4), 1);
                    break;
                }
                case 2: { // alphanumeric
                    int n = in.read(new int[]{9, 11, 13}[sizeClass]);
                    while (n >= 2) {
                        int v = in.read(11);
                        if (v / 45 >= 45) return null;
                        out.write(ALNUM.charAt(v / 45));
                        out.write(ALNUM.charAt(v % 45));
                        n -= 2;
                    }
                    if (n == 1) {
                        int v = in.read(6);
                        if (v >= 45) return null;
                        out.write(ALNUM.charAt(v));
                    }
                    break;
                }
                case 4: { // bytes
                    int n = in.read(new int[]{8, 16, 16}[sizeClass]);
                    if (n * 8 > in.left()) return null;
                    for (int i = 0; i < n; i++) out.write(in.read(8));
                    break;
                }
                case 8: { // kanji, as Shift JIS
                    int n = in.read(new int[]{8, 10, 12}[sizeClass]);
                    ByteArrayOutputStream sj = new ByteArrayOutputStream();
                    for (int i = 0; i < n; i++) {
                        int v = in.read(13);
                        int a = ((v / 0xC0) << 8) | (v % 0xC0);
                        a += a < 0x1F00 ? 0x8140 : 0xC140;
                        sj.write(a >> 8);
                        sj.write(a & 0xff);
                    }
                    try {
                        byte[] u = new String(sj.toByteArray(), Charset.forName("Shift_JIS")).getBytes(StandardCharsets.UTF_8);
                        out.write(u, 0, u.length);
                    } catch (RuntimeException e) {
                        return null;
                    }
                    break;
                }
                case 7: { // ECI: a character set number; the text is read as UTF-8 anyway
                    int v = in.read(8);
                    if ((v & 0x80) != 0) in.read((v & 0xC0) == 0x80 ? 8 : 16);
                    break;
                }
                case 3: in.read(16); break; // structured append header
                case 5: break;              // FNC1, first position
                case 9: in.read(8); break;  // FNC1, second position
                default: return null;
            }
            if (in.overrun) return null;
        }
        return new String(out.toByteArray(), StandardCharsets.UTF_8);
    }

    private static void appendNum(ByteArrayOutputStream out, int v, int digits) {
        String s = Integer.toString(v);
        if (s.length() > digits) s = s.substring(s.length() - digits);
        for (int i = s.length(); i < digits; i++) out.write('0');
        for (int i = 0; i < s.length(); i++) out.write(s.charAt(i));
    }

    private static final class Bits {
        final byte[] d;
        int pos;
        boolean overrun;
        Bits(byte[] d) { this.d = d; }
        int left() { return d.length * 8 - pos; }
        int read(int n) {
            int v = 0;
            for (int i = 0; i < n; i++) {
                if (pos >= d.length * 8) { overrun = true; return 0; }
                v = v << 1 | ((d[pos >>> 3] >>> (7 - (pos & 7))) & 1);
                pos++;
            }
            return v;
        }
    }

    // ---- Reed-Solomon over GF(256) ----

    static final class ReedSolomon {
        private static final int[] EXP = new int[512], LOG = new int[256];
        static {
            int x = 1;
            for (int i = 0; i < 255; i++) {
                EXP[i] = x;
                LOG[x] = i;
                x <<= 1;
                if (x >= 256) x ^= 0x11D;
            }
            for (int i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
        }

        static int mul(int a, int b) {
            return a == 0 || b == 0 ? 0 : EXP[LOG[a] + LOG[b]];
        }

        static int div(int a, int b) {
            return a == 0 ? 0 : EXP[LOG[a] + 255 - LOG[b]];
        }

        /** Corrects a block (data then ecc codewords) in place; false if it can't. */
        static boolean correct(int[] c, int ecc) {
            int n = c.length;
            int[] s = new int[ecc];
            boolean clean = true;
            for (int j = 0; j < ecc; j++) {
                int v = 0;
                for (int i = 0; i < n; i++) v = mul(v, EXP[j]) ^ c[i];
                s[j] = v;
                if (v != 0) clean = false;
            }
            if (clean) return true;
            // Berlekamp-Massey: the error locator, lowest power first.
            int[] C = new int[ecc + 1], B = new int[ecc + 1];
            C[0] = B[0] = 1;
            int L = 0, m = 1, bb = 1;
            for (int k = 0; k < ecc; k++) {
                int d = s[k];
                for (int i = 1; i <= L; i++) d ^= mul(C[i], s[k - i]);
                if (d == 0) { m++; continue; }
                int coef = div(d, bb);
                if (2 * L <= k) {
                    int[] T = C.clone();
                    for (int i = 0; i + m <= ecc; i++) C[i + m] ^= mul(coef, B[i]);
                    L = k + 1 - L;
                    B = T;
                    bb = d;
                    m = 1;
                } else {
                    for (int i = 0; i + m <= ecc; i++) C[i + m] ^= mul(coef, B[i]);
                    m++;
                }
            }
            if (2 * L > ecc) return false;
            // Omega = S * Lambda mod x^ecc
            int[] om = new int[ecc];
            for (int i = 0; i < ecc; i++)
                for (int j = 0; j <= Math.min(i, L); j++) om[i] ^= mul(C[j], s[i - j]);
            int roots = 0;
            for (int i = 0; i < n; i++) {
                int pw = n - 1 - i;                 // position i is the x^pw coefficient
                int xinv = EXP[(255 - pw % 255) % 255]; // X^-1
                int lam = 0;
                for (int j = L; j >= 0; j--) lam = mul(lam, xinv) ^ C[j];
                if (lam != 0) continue;
                roots++;
                int o = 0;
                for (int j = ecc - 1; j >= 0; j--) o = mul(o, xinv) ^ om[j];
                int dl = 0; // the formal derivative: odd terms only
                for (int j = 1; j <= L; j += 2) dl ^= mul(C[j], j - 1 == 0 ? 1 : pow(xinv, j - 1));
                if (dl == 0) return false;
                c[i] ^= mul(EXP[pw % 255], div(o, dl));
            }
            return roots == L;
        }

        private static int pow(int a, int e) {
            return a == 0 ? 0 : EXP[(LOG[a] * e) % 255];
        }
    }
}
