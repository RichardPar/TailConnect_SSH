package tailconnect.ssh;

import android.Manifest;
import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.ImageFormat;
import android.graphics.Matrix;
import android.graphics.SurfaceTexture;
import android.hardware.camera2.CameraAccessException;
import android.hardware.camera2.CameraCaptureSession;
import android.hardware.camera2.CameraCharacteristics;
import android.hardware.camera2.CameraDevice;
import android.hardware.camera2.CameraManager;
import android.hardware.camera2.CaptureRequest;
import android.hardware.camera2.params.StreamConfigurationMap;
import android.hardware.display.DisplayManager;
import android.media.Image;
import android.media.ImageReader;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.HandlerThread;
import android.util.Size;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.Surface;
import android.view.TextureView;
import android.widget.Button;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.TextView;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * A full-screen camera view that looks for a QR code in every frame (with
 * {@link QrDecoder}) and returns its text as {@link #EXTRA_TEXT}. Uses the
 * back camera; asks for the camera permission itself.
 */
public class QrScanActivity extends Activity {
    static final String EXTRA_TEXT = "text";
    private static final int REQ_CAMERA = 1;

    private TextureView preview;
    private TextView hint;
    private HandlerThread thread;
    private Handler bg;
    // The camera's callbacks run on the background thread, start and stop on
    // the UI thread: camLock guards these, and active says whether the
    // camera is wanted (false after stop, so a late open is closed at once).
    private final Object camLock = new Object();
    private boolean active;
    private CameraDevice camera;
    private CameraCaptureSession session;
    private ImageReader reader;
    private Size size;
    private int sensorOrientation;
    private volatile boolean busy, done;
    private DisplayManager.DisplayListener rotation;

    @Override
    protected void onCreate(Bundle saved) {
        super.onCreate(saved);
        FrameLayout root = new FrameLayout(this);
        root.setBackgroundColor(0xFF000000);
        preview = new TextureView(this);
        root.addView(preview, new FrameLayout.LayoutParams(-1, -1));
        // A dimmed screen with a clear square to aim with, its corners in teal.
        root.addView(new Viewfinder(this), new FrameLayout.LayoutParams(-1, -1));

        LinearLayout top = new LinearLayout(this);
        top.setOrientation(LinearLayout.VERTICAL);
        top.setGravity(Gravity.CENTER_HORIZONTAL);
        top.setPadding(dp(24), dp(48), dp(24), 0);
        TextView title = new TextView(this);
        title.setText("Scan to join");
        title.setTextColor(0xFFFFFFFF);
        title.setTextSize(TypedValue.COMPLEX_UNIT_SP, 22);
        title.setTypeface(android.graphics.Typeface.create("sans-serif-medium", android.graphics.Typeface.NORMAL));
        top.addView(title);
        hint = new TextView(this);
        hint.setText("Point the camera at the QR code next to a new auth key in your hub's web portal.");
        hint.setTextColor(0xCCFFFFFF);
        hint.setTextSize(TypedValue.COMPLEX_UNIT_SP, 14);
        hint.setGravity(Gravity.CENTER);
        hint.setPadding(0, dp(8), 0, 0);
        top.addView(hint);
        root.addView(top, new FrameLayout.LayoutParams(-1, -2, Gravity.TOP));

        TextView cancel = new TextView(this);
        cancel.setText("Cancel");
        cancel.setTextColor(0xFFFFFFFF);
        cancel.setTextSize(TypedValue.COMPLEX_UNIT_SP, 16);
        cancel.setGravity(Gravity.CENTER);
        cancel.setPadding(dp(32), dp(12), dp(32), dp(12));
        android.graphics.drawable.GradientDrawable bg = new android.graphics.drawable.GradientDrawable();
        bg.setCornerRadius(dp(24));
        bg.setColor(0x33FFFFFF);
        bg.setStroke(dp(1), 0x66FFFFFF);
        cancel.setBackground(bg);
        cancel.setOnClickListener(v -> finish());
        FrameLayout.LayoutParams lp = new FrameLayout.LayoutParams(-2, -2, Gravity.BOTTOM | Gravity.CENTER_HORIZONTAL);
        lp.bottomMargin = dp(48);
        root.addView(cancel, lp);
        setContentView(root);

        preview.setSurfaceTextureListener(new TextureView.SurfaceTextureListener() {
            @Override public void onSurfaceTextureAvailable(SurfaceTexture s, int w, int h) { start(); }
            @Override public void onSurfaceTextureSizeChanged(SurfaceTexture s, int w, int h) { fitPreview(); }
            @Override public boolean onSurfaceTextureDestroyed(SurfaceTexture s) { return true; }
            @Override public void onSurfaceTextureUpdated(SurfaceTexture s) {}
        });
        // A 180° turn changes neither the configuration nor the view's size.
        rotation = new DisplayManager.DisplayListener() {
            @Override public void onDisplayAdded(int id) {}
            @Override public void onDisplayRemoved(int id) {}
            @Override public void onDisplayChanged(int id) { fitPreview(); }
        };
    }

    @Override
    protected void onResume() {
        super.onResume();
        ((DisplayManager) getSystemService(Context.DISPLAY_SERVICE)).registerDisplayListener(rotation, null);
        thread = new HandlerThread("qr-camera");
        thread.start();
        bg = new Handler(thread.getLooper());
        if (checkSelfPermission(Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[]{Manifest.permission.CAMERA}, REQ_CAMERA);
            return;
        }
        if (preview.isAvailable()) start();
    }

    @Override
    protected void onPause() {
        ((DisplayManager) getSystemService(Context.DISPLAY_SERVICE)).unregisterDisplayListener(rotation);
        stop();
        thread.quitSafely();
        thread = null;
        bg = null;
        super.onPause();
    }

    @Override
    public void onRequestPermissionsResult(int request, String[] perms, int[] results) {
        if (request != REQ_CAMERA) return;
        if (results.length > 0 && results[0] == PackageManager.PERMISSION_GRANTED) {
            if (preview.isAvailable()) start();
        } else {
            hint.setText("TailConnect needs the camera to read the QR code. Allow it in Settings, or type the key in.");
        }
    }

    // ---- the camera ----

    private void start() {
        if (camera != null || bg == null || done) return;
        if (checkSelfPermission(Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) return;
        CameraManager cm = (CameraManager) getSystemService(Context.CAMERA_SERVICE);
        try {
            String id = pickCamera(cm);
            if (id == null) {
                hint.setText("This device has no camera that can be used.");
                return;
            }
            CameraCharacteristics cc = cm.getCameraCharacteristics(id);
            Integer so = cc.get(CameraCharacteristics.SENSOR_ORIENTATION);
            sensorOrientation = so != null ? so : 90;
            StreamConfigurationMap map = cc.get(CameraCharacteristics.SCALER_STREAM_CONFIGURATION_MAP);
            size = pickSize(map);
            int[] af = cc.get(CameraCharacteristics.CONTROL_AF_AVAILABLE_MODES);
            boolean continuousAf = af != null && Arrays.stream(af).anyMatch(m -> m == CaptureRequest.CONTROL_AF_MODE_CONTINUOUS_PICTURE);

            synchronized (camLock) {
                active = true;
                reader = ImageReader.newInstance(size.getWidth(), size.getHeight(), ImageFormat.YUV_420_888, 2);
                reader.setOnImageAvailableListener(this::onFrame, bg);
            }
            cm.openCamera(id, new CameraDevice.StateCallback() {
                @Override public void onOpened(CameraDevice d) {
                    synchronized (camLock) {
                        if (!active) { d.close(); return; } // stopped while opening
                        camera = d;
                    }
                    startSession(continuousAf);
                }
                @Override public void onDisconnected(CameraDevice d) {
                    d.close();
                    synchronized (camLock) { if (camera == d) camera = null; }
                }
                @Override public void onError(CameraDevice d, int error) {
                    d.close();
                    synchronized (camLock) { if (camera == d) camera = null; }
                    runOnUiThread(() -> hint.setText("The camera couldn't be opened (it may be in use by another app)."));
                }
            }, bg);
            runOnUiThread(this::fitPreview);
        } catch (CameraAccessException | SecurityException | IllegalArgumentException e) {
            hint.setText("The camera couldn't be opened: " + e.getMessage());
        }
    }

    private void startSession(boolean continuousAf) {
        try {
            SurfaceTexture st = preview.getSurfaceTexture();
            CameraDevice dev;
            Surface frames;
            synchronized (camLock) {
                if (st == null || camera == null || reader == null) return;
                dev = camera;
                frames = reader.getSurface();
            }
            st.setDefaultBufferSize(size.getWidth(), size.getHeight());
            Surface view = new Surface(st);
            CaptureRequest.Builder req = dev.createCaptureRequest(CameraDevice.TEMPLATE_PREVIEW);
            req.addTarget(view);
            req.addTarget(frames);
            if (continuousAf) req.set(CaptureRequest.CONTROL_AF_MODE, CaptureRequest.CONTROL_AF_MODE_CONTINUOUS_PICTURE);
            dev.createCaptureSession(Arrays.asList(view, frames), new CameraCaptureSession.StateCallback() {
                @Override public void onConfigured(CameraCaptureSession s) {
                    synchronized (camLock) {
                        if (camera != dev) { s.close(); return; }
                        session = s;
                    }
                    try {
                        s.setRepeatingRequest(req.build(), null, bg);
                    } catch (CameraAccessException | IllegalStateException e) {
                        // closed while starting: onPause tidies up
                    }
                }
                @Override public void onConfigureFailed(CameraCaptureSession s) {
                    runOnUiThread(() -> hint.setText("The camera couldn't be started."));
                }
            }, bg);
        } catch (CameraAccessException | IllegalStateException e) {
            runOnUiThread(() -> hint.setText("The camera couldn't be started: " + e.getMessage()));
        }
    }

    private void stop() {
        synchronized (camLock) {
            active = false;
            if (session != null) { session.close(); session = null; }
            if (camera != null) { camera.close(); camera = null; }
            if (reader != null) { reader.close(); reader = null; }
        }
    }

    /** The back camera, or failing that any camera. */
    private static String pickCamera(CameraManager cm) throws CameraAccessException {
        String any = null;
        for (String id : cm.getCameraIdList()) {
            Integer facing = cm.getCameraCharacteristics(id).get(CameraCharacteristics.LENS_FACING);
            if (facing != null && facing == CameraCharacteristics.LENS_FACING_BACK) return id;
            if (any == null) any = id;
        }
        return any;
    }

    /**
     * The largest size up to 1920×1080 that both the preview and the frame
     * reader support: enough detail for a dense code, quick to scan.
     */
    private static Size pickSize(StreamConfigurationMap map) {
        Set<Size> views = new HashSet<>(Arrays.asList(map.getOutputSizes(SurfaceTexture.class)));
        Size best = null;
        for (Size s : map.getOutputSizes(ImageFormat.YUV_420_888)) {
            if (!views.contains(s) || s.getWidth() * s.getHeight() > 1920 * 1080) continue;
            if (best == null || s.getWidth() * s.getHeight() > best.getWidth() * best.getHeight()) best = s;
        }
        return best != null ? best : new Size(640, 480);
    }

    /**
     * Shows the preview upright and undistorted, filling the screen. The
     * view stretches the camera's picture (already turned for the device's
     * natural orientation) to its own shape; this undoes the stretch, turns
     * it for the current rotation and scales it to cover the view.
     */
    private void fitPreview() {
        if (size == null) return;
        float W = preview.getWidth(), H = preview.getHeight();
        if (W == 0 || H == 0) return;
        boolean sideways = sensorOrientation % 180 != 0;
        float nw = sideways ? size.getHeight() : size.getWidth(), nh = sideways ? size.getWidth() : size.getHeight();
        // Activity.getDisplay() only exists from Android 11 (API 30).
        @SuppressWarnings("deprecation")
        int rot = Build.VERSION.SDK_INT >= 30 ? getDisplay().getRotation() : getWindowManager().getDefaultDisplay().getRotation();
        int deg = 90 * rot;
        float cw = deg % 180 == 0 ? nw : nh, ch = deg % 180 == 0 ? nh : nw;
        float cx = W / 2, cy = H / 2, s = Math.max(W / cw, H / ch);
        Matrix m = new Matrix();
        m.postScale(nw / W, nh / H, cx, cy);
        m.postRotate(-deg, cx, cy);
        m.postScale(s, s, cx, cy);
        preview.setTransform(m);
    }

    // ---- reading frames ----

    /** Copies a frame's brightness and looks for a code, skipping frames while busy. */
    private void onFrame(ImageReader r) {
        Image img = r.acquireLatestImage();
        if (img == null) return;
        if (busy || done) { img.close(); return; }
        Image.Plane y = img.getPlanes()[0];
        int w = img.getWidth(), h = img.getHeight();
        int rowStride = y.getRowStride(), pixStride = y.getPixelStride();
        ByteBuffer buf = y.getBuffer();
        byte[] lum = new byte[w * h];
        if (pixStride == 1) {
            for (int row = 0; row < h; row++) {
                buf.position(row * rowStride);
                buf.get(lum, row * w, w);
            }
        } else {
            for (int row = 0; row < h; row++)
                for (int col = 0; col < w; col++) lum[row * w + col] = buf.get(row * rowStride + col * pixStride);
        }
        img.close();
        busy = true;
        // Decode on a second thread, so the camera's thread keeps dropping stale frames.
        new Thread(() -> {
            String text = QrDecoder.decode(lum, w, h, w);
            busy = false;
            if (text != null && !done) {
                done = true;
                runOnUiThread(() -> {
                    setResult(RESULT_OK, new Intent().putExtra(EXTRA_TEXT, text));
                    finish();
                });
            }
        }, "qr-decode").start();
    }

    private int dp(int v) {
        return Math.round(v * getResources().getDisplayMetrics().density);
    }

    /** The dimmed overlay with a clear, teal-cornered square and a sweeping line. */
    private static final class Viewfinder extends android.view.View {
        private final android.graphics.Paint dim = new android.graphics.Paint();
        private final android.graphics.Paint corner = new android.graphics.Paint(android.graphics.Paint.ANTI_ALIAS_FLAG);
        private final android.graphics.Paint line = new android.graphics.Paint(android.graphics.Paint.ANTI_ALIAS_FLAG);
        private final float d;
        private final long t0 = System.currentTimeMillis();

        Viewfinder(Context c) {
            super(c);
            d = c.getResources().getDisplayMetrics().density;
            dim.setColor(0x99000000);
            corner.setColor(0xFF14B8A6);
            corner.setStyle(android.graphics.Paint.Style.STROKE);
            corner.setStrokeWidth(4 * d);
            corner.setStrokeCap(android.graphics.Paint.Cap.ROUND);
            line.setColor(0xAA14B8A6);
            line.setStrokeWidth(2 * d);
        }

        @Override
        protected void onDraw(android.graphics.Canvas c) {
            float w = getWidth(), h = getHeight(), side = Math.min(w, h) * 0.68f;
            float l = (w - side) / 2, t = (h - side) / 2, r = l + side, b = t + side;
            c.drawRect(0, 0, w, t, dim);
            c.drawRect(0, b, w, h, dim);
            c.drawRect(0, t, l, b, dim);
            c.drawRect(r, t, w, b, dim);
            float k = 28 * d;
            c.drawLine(l, t + k, l, t, corner); c.drawLine(l, t, l + k, t, corner);
            c.drawLine(r - k, t, r, t, corner); c.drawLine(r, t, r, t + k, corner);
            c.drawLine(l, b - k, l, b, corner); c.drawLine(l, b, l + k, b, corner);
            c.drawLine(r - k, b, r, b, corner); c.drawLine(r, b, r, b - k, corner);
            float phase = ((System.currentTimeMillis() - t0) % 2400) / 2400f;
            float y = t + side * (0.5f - 0.42f * (float) Math.cos(phase * 2 * Math.PI));
            c.drawLine(l + 12 * d, y, r - 12 * d, y, line);
            postInvalidateOnAnimation();
        }
    }
}
