package tailconnect.ssh;

import android.content.Context;
import android.content.res.ColorStateList;
import android.content.res.Configuration;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.RectF;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.widget.TextView;

/**
 * The look, shared with the Linux and Windows apps: colours, the header
 * card's gradients and rings, the state emblem, avatars, chips and the
 * small drawn icons. Everything is drawn in code, with no libraries.
 */
final class Ui {
    private Ui() {}

    static final int TEAL = 0xFF0D9488, GREEN = 0xFF16A34A, BLUE = 0xFF2563EB, VIOLET = 0xFF7C3AED,
            AMBER = 0xFFD97706, SLATE = 0xFF64748B, RED = 0xFFDC2626;

    /** Colours that follow the system's light or dark theme. */
    static final class Pal {
        int bg, card, border, text, weak, button;
        boolean dark;
    }

    static Pal pal(Context c) {
        Pal p = new Pal();
        p.dark = (c.getResources().getConfiguration().uiMode & Configuration.UI_MODE_NIGHT_MASK) == Configuration.UI_MODE_NIGHT_YES;
        if (p.dark) {
            p.bg = 0xFF111418; p.card = 0xFF1C2128; p.border = 0xFF2B313A; p.text = 0xFFE6E9EE; p.weak = 0xFF949CA8; p.button = 0xFF262C34;
        } else {
            p.bg = 0xFFF3F5F8; p.card = 0xFFFFFFFF; p.border = 0xFFE3E7EC; p.text = 0xFF14181F; p.weak = 0xFF6B7280; p.button = 0xFFECEFF3;
        }
        return p;
    }

    static int dp(Context c, float v) {
        return Math.round(TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, v, c.getResources().getDisplayMetrics()));
    }

    static GradientDrawable rounded(int color, float radiusPx, int strokeColor, int strokePx) {
        GradientDrawable g = new GradientDrawable();
        g.setColor(color);
        g.setCornerRadius(radiusPx);
        if (strokePx > 0) g.setStroke(strokePx, strokeColor);
        return g;
    }

    /** The header's gradient for a look. */
    static GradientDrawable heroBackground(Context c, Words.Look look) {
        int[] colors;
        switch (look) {
            case CONNECTED: colors = new int[]{0xFF14B8A6, 0xFF0E5F86}; break;
            case ATTENTION: colors = new int[]{0xFFF59E0B, 0xFFC2410C}; break;
            default: colors = new int[]{0xFF5F6B7E, 0xFF2F3745};
        }
        GradientDrawable g = new GradientDrawable(GradientDrawable.Orientation.TL_BR, colors);
        g.setCornerRadius(dp(c, 22));
        return g;
    }

    static Typeface medium() {
        return Typeface.create("sans-serif-medium", Typeface.NORMAL);
    }

    static TextView text(Context c, String s, float sp, int color) {
        TextView t = new TextView(c);
        t.setText(s);
        t.setTextSize(TypedValue.COMPLEX_UNIT_SP, sp);
        t.setTextColor(color);
        return t;
    }

    /** A small rounded label in a colour. */
    static TextView chip(Context c, String s, int color) {
        TextView t = text(c, s, 11, color);
        t.setTypeface(medium());
        t.setPadding(dp(c, 7), dp(c, 1), dp(c, 7), dp(c, 2));
        t.setBackground(rounded((color & 0x00FFFFFF) | 0x24000000, dp(c, 8), 0, 0));
        return t;
    }

    static int chipColor(String name) {
        switch (name) {
            case "green": return GREEN;
            case "blue": return BLUE;
            case "violet": return VIOLET;
            default: return SLATE;
        }
    }

    /** A primary button: white text on teal. */
    static TextView primary(Context c, String s) {
        TextView t = text(c, s, 15, 0xFFFFFFFF);
        t.setTypeface(medium());
        t.setGravity(Gravity.CENTER);
        t.setPadding(dp(c, 24), dp(c, 12), dp(c, 24), dp(c, 12));
        t.setBackground(rounded(TEAL, dp(c, 24), 0, 0));
        t.setClickable(true);
        return t;
    }

    /** A quiet button: text on a light pill. */
    static TextView secondary(Context c, Pal p, String s) {
        TextView t = text(c, s, 15, p.text);
        t.setTypeface(medium());
        t.setGravity(Gravity.CENTER);
        t.setPadding(dp(c, 20), dp(c, 12), dp(c, 20), dp(c, 12));
        t.setBackground(rounded(p.button, dp(c, 24), 0, 0));
        t.setClickable(true);
        return t;
    }

    static void tintSwitch(android.widget.Switch s) {
        int[][] states = {{android.R.attr.state_checked}, {}};
        s.setThumbTintList(new ColorStateList(states, new int[]{TEAL, 0xFFFFFFFF}));
        s.setTrackTintList(new ColorStateList(states, new int[]{0xEEFFFFFF, 0x66FFFFFF}));
    }

    // ---- drawn views ----

    /** Faint rings in the header's top right corner: the network. */
    static final class Rings extends View {
        private final Paint ring = new Paint(Paint.ANTI_ALIAS_FLAG), dot = new Paint(Paint.ANTI_ALIAS_FLAG);
        private final float d;

        Rings(Context c) {
            super(c);
            d = c.getResources().getDisplayMetrics().density;
            ring.setStyle(Paint.Style.STROKE);
            ring.setStrokeWidth(1.3f * d);
            ring.setColor(Color.WHITE);
            dot.setColor(Color.WHITE);
        }

        /** Take the card's size, never set it (it fills the card behind the text). */
        @Override
        protected void onMeasure(int w, int h) {
            setMeasuredDimension(MeasureSpec.getMode(w) == MeasureSpec.EXACTLY ? MeasureSpec.getSize(w) : 0,
                    MeasureSpec.getMode(h) == MeasureSpec.EXACTLY ? MeasureSpec.getSize(h) : 0);
        }

        @Override
        protected void onDraw(Canvas c) {
            float cx = getWidth() - 40 * d, cy = 40 * d;
            float[][] rs = {{34, 0.17f}, {60, 0.11f}, {88, 0.07f}, {118, 0.045f}};
            for (float[] r : rs) {
                ring.setAlpha((int) (255 * r[1]));
                c.drawCircle(cx, cy, r[0] * d, ring);
            }
            dot.setAlpha(90);
            c.drawCircle(cx - 42 * d, cy + 42 * d, 3 * d, dot);
            dot.setAlpha(64);
            c.drawCircle(cx - 88 * d, cy + 10 * d, 2.4f * d, dot);
            dot.setAlpha(50);
            c.drawCircle(cx - 20 * d, cy + 112 * d, 2.2f * d, dot);
        }
    }

    /** The state's emblem: a ring and dot (a node on the network), or "!". */
    static final class Emblem extends View {
        private final Paint p = new Paint(Paint.ANTI_ALIAS_FLAG);
        private final float d;
        Words.Look look = Words.Look.DISCONNECTED;

        Emblem(Context c) {
            super(c);
            d = c.getResources().getDisplayMetrics().density;
        }

        @Override
        protected void onDraw(Canvas c) {
            float cx = getWidth() / 2f, cy = getHeight() / 2f, r = Math.min(cx, cy);
            p.setStyle(Paint.Style.FILL);
            p.setColor(0x2EFFFFFF);
            c.drawCircle(cx, cy, r, p);
            p.setColor(Color.WHITE);
            if (look == Words.Look.ATTENTION) {
                c.drawRoundRect(new RectF(cx - 2 * d, cy - 11 * d, cx + 2 * d, cy + 3 * d), 2 * d, 2 * d, p);
                c.drawCircle(cx, cy + 8 * d, 2.4f * d, p);
            } else {
                p.setStyle(Paint.Style.STROKE);
                p.setStrokeWidth(2.4f * d);
                c.drawCircle(cx, cy, r * 0.48f, p);
                p.setStyle(Paint.Style.FILL);
                c.drawCircle(cx, cy, r * 0.17f, p);
            }
        }
    }

    /** A circle with a machine's initial in a colour of its own, and an online dot. */
    static final class Avatar extends View {
        private static final int[] COLORS = {0xFF0D9488, 0xFF2563EB, 0xFF7C3AED, 0xFFDB2777, 0xFFEA580C, 0xFF059669, 0xFF4F46E5, 0xFF0891B2};
        private final Paint p = new Paint(Paint.ANTI_ALIAS_FLAG);
        private final float d;
        private String initial = "", name = "";
        private boolean online;
        private int ring;

        Avatar(Context c, int ringColor) {
            super(c);
            d = c.getResources().getDisplayMetrics().density;
            ring = ringColor;
            p.setTextAlign(Paint.Align.CENTER);
            p.setTypeface(medium());
        }

        void set(String name, boolean online) {
            this.name = name;
            this.initial = name.isEmpty() ? "" : name.substring(0, 1).toUpperCase(java.util.Locale.ROOT);
            this.online = online;
            invalidate();
        }

        @Override
        protected void onDraw(Canvas c) {
            float r = Math.min(getWidth(), getHeight()) / 2f, cx = r, cy = r;
            int h = 0;
            for (char ch : name.toCharArray()) h = h * 31 + ch;
            p.setStyle(Paint.Style.FILL);
            p.setColor(online ? COLORS[Math.floorMod(h, COLORS.length)] : 0xFF8A94A6);
            c.drawCircle(cx, cy, r, p);
            p.setColor(Color.WHITE);
            p.setTextSize(r * 0.95f);
            c.drawText(initial, cx, cy - (p.descent() + p.ascent()) / 2, p);
            float dx = cx + r * 0.72f, dy = cy + r * 0.72f;
            p.setColor(ring);
            c.drawCircle(dx, dy, 6.5f * d, p);
            p.setColor(online ? GREEN : SLATE);
            c.drawCircle(dx, dy, 4.5f * d, p);
        }
    }

    enum Glyph { COPY, WEB, KEY, LOGOUT, SCAN, WARNING, LOG, EXIT }

    /** Small line icons, drawn. */
    static final class Icon extends View {
        private final Paint p = new Paint(Paint.ANTI_ALIAS_FLAG);
        private final float d;
        private final Glyph g;

        Icon(Context c, Glyph g, int color) {
            super(c);
            this.g = g;
            d = c.getResources().getDisplayMetrics().density;
            p.setColor(color);
            p.setStyle(Paint.Style.STROKE);
            p.setStrokeWidth(1.7f * d);
            p.setStrokeCap(Paint.Cap.ROUND);
            p.setStrokeJoin(Paint.Join.ROUND);
        }

        void setColor(int color) {
            p.setColor(color);
            invalidate();
        }

        @Override
        protected void onDraw(Canvas c) {
            float s = Math.min(getWidth(), getHeight()), u = s / 20f;
            c.save();
            c.translate((getWidth() - s) / 2, (getHeight() - s) / 2);
            Path path = new Path();
            switch (g) {
                case COPY:
                    c.drawRoundRect(new RectF(7 * u, 7 * u, 17 * u, 17 * u), 2 * u, 2 * u, p);
                    path.moveTo(13 * u, 4 * u); path.lineTo(5 * u, 4 * u);
                    path.quadTo(3 * u, 4 * u, 3 * u, 6 * u); path.lineTo(3 * u, 13 * u);
                    c.drawPath(path, p);
                    break;
                case WEB:
                    c.drawCircle(10 * u, 10 * u, 7 * u, p);
                    c.drawOval(new RectF(6.5f * u, 3 * u, 13.5f * u, 17 * u), p);
                    c.drawLine(3 * u, 10 * u, 17 * u, 10 * u, p);
                    break;
                case KEY:
                    c.drawCircle(7 * u, 10 * u, 3.5f * u, p);
                    c.drawLine(10.5f * u, 10 * u, 17 * u, 10 * u, p);
                    c.drawLine(15 * u, 10 * u, 15 * u, 13 * u, p);
                    c.drawLine(17 * u, 10 * u, 17 * u, 12.5f * u, p);
                    break;
                case LOGOUT:
                    path.moveTo(9 * u, 4 * u); path.lineTo(5 * u, 4 * u); path.lineTo(5 * u, 16 * u); path.lineTo(9 * u, 16 * u);
                    c.drawPath(path, p);
                    c.drawLine(9 * u, 10 * u, 17 * u, 10 * u, p);
                    c.drawLine(14 * u, 7 * u, 17 * u, 10 * u, p);
                    c.drawLine(14 * u, 13 * u, 17 * u, 10 * u, p);
                    break;
                case SCAN:
                    float k = 4 * u;
                    c.drawLine(3 * u, 3 * u + k, 3 * u, 3 * u, p); c.drawLine(3 * u, 3 * u, 3 * u + k, 3 * u, p);
                    c.drawLine(17 * u - k, 3 * u, 17 * u, 3 * u, p); c.drawLine(17 * u, 3 * u, 17 * u, 3 * u + k, p);
                    c.drawLine(3 * u, 17 * u - k, 3 * u, 17 * u, p); c.drawLine(3 * u, 17 * u, 3 * u + k, 17 * u, p);
                    c.drawLine(17 * u - k, 17 * u, 17 * u, 17 * u, p); c.drawLine(17 * u, 17 * u, 17 * u, 17 * u - k, p);
                    c.drawLine(6 * u, 10 * u, 14 * u, 10 * u, p);
                    break;
                case WARNING:
                    path.moveTo(10 * u, 3 * u); path.lineTo(18 * u, 17 * u); path.lineTo(2 * u, 17 * u); path.close();
                    c.drawPath(path, p);
                    c.drawLine(10 * u, 8 * u, 10 * u, 12 * u, p);
                    c.drawPoint(10 * u, 14.5f * u, p);
                    break;
                case LOG:
                    c.drawRoundRect(new RectF(4 * u, 3 * u, 16 * u, 17 * u), 2 * u, 2 * u, p);
                    c.drawLine(7 * u, 7 * u, 13 * u, 7 * u, p);
                    c.drawLine(7 * u, 10 * u, 13 * u, 10 * u, p);
                    c.drawLine(7 * u, 13 * u, 11 * u, 13 * u, p);
                    break;
                case EXIT:
                    c.drawCircle(10 * u, 10 * u, 7 * u, p);
                    c.drawLine(10 * u, 3 * u, 10 * u, 17 * u, p);
                    path.moveTo(4 * u, 6.5f * u); path.quadTo(10 * u, 9 * u, 16 * u, 6.5f * u);
                    path.moveTo(4 * u, 13.5f * u); path.quadTo(10 * u, 11 * u, 16 * u, 13.5f * u);
                    c.drawPath(path, p);
                    break;
            }
            c.restore();
        }
    }
}
