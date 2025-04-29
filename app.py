import streamlit as st
import cv2
import numpy as np
import tempfile
import easyocr
from roboflow import Roboflow
import hashlib
import os
import zipfile
import imghdr
import streamlit.components.v1 as components
import base64
import json

# Set up Streamlit page
st.set_page_config(page_title="Smart Number Plate Detection with Browser Webcam", layout="centered", initial_sidebar_state="expanded")

# Initialize session state
if "authenticated" not in st.session_state:
    st.session_state["authenticated"] = False
if "model" not in st.session_state:
    st.session_state["model"] = None
if "reader" not in st.session_state:
    st.session_state["reader"] = None
if "webcam_data" not in st.session_state:
    st.session_state["webcam_data"] = None

USER_CREDENTIALS = {
    "admin": "admin123",
    "user1": "password123",
}

def encrypt_data(data):
    hashed_data = {}
    for plate, details in data.items():
        plate_hash = hashlib.sha256(plate.encode()).hexdigest()
        hashed_data[plate_hash] = details
    return hashed_data

encrypted_stolen_plates = encrypt_data({
    "LSI5EBC": "Reported stolen - Chennai",
    "SN6EXMZ": "Police Alert - Bengaluru",
    "MH12ZZ0001": "Missing vehicle - Pune"
})

def login():
    st.title("🔒 Login to Access Detection System")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        if username in USER_CREDENTIALS and USER_CREDENTIALS[username] == password:
            st.session_state["authenticated"] = True
            st.success(f"Welcome, {username}!")
            st.rerun()
        else:
            st.error("Invalid username or password. Please try again.")

def is_malicious_image(file):
    file.seek(0)
    header_type = imghdr.what(None, h=file.read(512))
    file.seek(0)
    return header_type not in ['jpeg', 'png']

def detect_number_plate(frame, predictions, reader):
    detections = []
    for prediction in predictions:
        x = prediction['x']
        y = prediction['y']
        width = prediction['width']
        height = prediction['height']
        
        x1 = int(x - width / 2)
        y1 = int(y - height / 2)
        x2 = int(x + width / 2)
        y2 = int(y + height / 2)
        
        x1, y1 = max(0, x1), max(0, y1)
        x2, y2 = min(frame.shape[1], x2), min(frame.shape[0], y2)
        
        plate_img = frame[y1:y2, x1:x2]
        if plate_img.size == 0:
            continue
        text = reader.readtext(plate_img, detail=0)
        plate_text = ''.join(text).replace(' ', '').upper()
        plate_hash = hashlib.sha256(plate_text.encode()).hexdigest()
        is_stolen = plate_hash in encrypted_stolen_plates
        detections.append((x1, y1, x2, y2, plate_text, is_stolen))
    
    return detections

def draw_detections(frame, detections):
    for x1, y1, x2, y2, plate_text, is_stolen in detections:
        color = (0, 0, 255) if is_stolen else (0, 255, 0)
        cv2.rectangle(frame, (x1, y1), (x2, y2), color, 2)
        cv2.putText(frame, plate_text, (x1, y1 - 10), cv2.FONT_HERSHEY_SIMPLEX, 0.8, (255, 255, 255), 2)
    return frame

def decode_base64_to_image(base64_str):
    try:
        img_data = base64.b64decode(base64_str)
        img_array = np.frombuffer(img_data, dtype=np.uint8)
        img = cv2.imdecode(img_array, 1)
        return img
    except:
        return None

def browser_webcam_component():
    st.title("Webcam Feed")
    webcam_html = """
    <!DOCTYPE html>
    <html>
    <head>
        <meta name="viewport" content="width=640, user-scalable=no" />
        <style>
            body {
                text-align: center;
                margin: 0;
                padding: 0;
                background: #f0f0f0;
            }
            video {
                width: 90vw;
                max-width: 1280px;
                height: auto;
                border: 3px solid black;
                border-radius: 10px;
            }
            canvas {
                position: absolute;
                pointer-events: none;
            }
            button {
                margin: 20px;
                padding: 14px 28px;
                font-size: 18px;
                border: none;
                border-radius: 5px;
                background-color: #3498db;
                color: white;
                cursor: pointer;
            }
            button:hover {
                background-color: #2980b9;
            }
            #fps {
                position: absolute;
                top: 10px;
                left: 10px;
                color: white;
                background: rgba(0, 0, 0, 0.7);
                padding: 5px;
                border-radius: 3px;
            }
        </style>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.5.1/jquery.min.js"></script>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/lodash.js/4.17.20/lodash.min.js"></script>
        <script src="https://cdn.jsdelivr.net/npm/inferencejs"></script>
    </head>
    <body class="loading">
        <div id="fps">0 FPS</div>
        <video id="webcam" autoplay playsinline></video>
        <br/>
        <button id="toggleDetection">Start Detection</button>
        <script>
            const { InferenceEngine, CVImage } = inferencejs;
            const inferEngine = new InferenceEngine();
            const video = document.getElementById('webcam');
            const toggleBtn = document.getElementById('toggleDetection');
            let canvas, ctx;
            let workerId;
            let isDetecting = false;
            let prevTime;
            let pastFrameTimes = [];

            // Initialize video stream
            navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } })
                .then(stream => {
                    video.srcObject = stream;
                    video.onloadeddata = () => {
                        video.play();
                        resizeCanvas();
                        document.body.classList.remove('loading');
                    };
                })
                .catch(error => console.error('Error accessing webcam:', error));

            // Initialize Roboflow model
            inferEngine.startWorker('license-z4tou', '1', 'rf_vIBRtlBNJRZYamwfQnQ2iB6p0eX2')
                .then(id => {
                    workerId = id;
                })
                .catch(error => console.error('Error loading model:', error));

            // Canvas setup
            function resizeCanvas() {
                if (canvas) canvas.remove();
                canvas = document.createElement('canvas');
                ctx = canvas.getContext('2d');
                canvas.width = video.videoWidth;
                canvas.height = video.videoHeight;
                const dimensions = videoDimensions();
                canvas.style.width = dimensions.width + 'px';
                canvas.style.height = dimensions.height + 'px';
                canvas.style.left = (window.innerWidth - dimensions.width) / 2 + 'px';
                canvas.style.top = (window.innerHeight - dimensions.height) / 2 + 'px';
                document.body.appendChild(canvas);
            }

            function videoDimensions() {
                const videoRatio = video.videoWidth / video.videoHeight;
                let width = video.offsetWidth, height = video.offsetHeight;
                const elementRatio = width / height;
                if (elementRatio > videoRatio) width = height * videoRatio;
                else height = width / videoRatio;
                return { width, height };
            }

            window.addEventListener('resize', resizeCanvas);

            // Render predictions
            function renderPredictions(predictions) {
                ctx.clearRect(0, 0, canvas.width, canvas.height);
                predictions.forEach(prediction => {
                    const x = prediction.bbox.x;
                    const y = prediction.bbox.y;
                    const width = prediction.bbox.width;
                    const height = prediction.bbox.height;

                    ctx.strokeStyle = '#00FF00';
                    ctx.lineWidth = 4;
                    ctx.strokeRect(x - width / 2, y - height / 2, width, height);

                    ctx.fillStyle = '#00FF00';
                    const textWidth = ctx.measureText(prediction.class).width;
                    const textHeight = 16;
                    ctx.fillRect(x - width / 2, y - height / 2 - textHeight - 4, textWidth + 8, textHeight + 4);

                    ctx.font = '16px sans-serif';
                    ctx.textBaseline = 'top';
                    ctx.fillStyle = '#000000';
                    ctx.fillText(prediction.class, x - width / 2 + 4, y - height / 2 - textHeight);
                });

                // Send frame and predictions to Streamlit
                canvas.toBlob(blob => {
                    const reader = new FileReader();
                    reader.onloadend = () => {
                        const base64data = reader.result.split(',')[1];
                        const predictionsData = predictions.map(p => ({
                            x: p.bbox.x,
                            y: p.bbox.y,
                            width: p.bbox.width,
                            height: p.bbox.height
                        }));
                        window.parent.postMessage({
                            type: 'webcam-data',
                            frame: base64data,
                            predictions: predictionsData
                        }, '*');
                    };
                    reader.readAsDataURL(blob);
                }, 'image/jpeg');
            }

            // Detect frames
            function detectFrame() {
                if (!isDetecting || !workerId) return requestAnimationFrame(detectFrame);
                const image = new CVImage(video);
                inferEngine.infer(workerId, image)
                    .then(predictions => {
                        renderPredictions(predictions);
                        updateFPS();
                        requestAnimationFrame(detectFrame);
                    })
                    .catch(error => {
                        console.error('Inference error:', error);
                        requestAnimationFrame(detectFrame);
                    });
            }

            function updateFPS() {
                const now = Date.now();
                if (prevTime) {
                    pastFrameTimes.push(now - prevTime);
                    if (pastFrameTimes.length > 30) pastFrameTimes.shift();
                    const total = pastFrameTimes.reduce((sum, t) => sum + t / 1000, 0);
                    const fps = Math.round(pastFrameTimes.length / total);
                    document.getElementById('fps').textContent = `${fps} FPS`;
                }
                prevTime = now;
            }

            // Toggle detection
            toggleBtn.addEventListener('click', () => {
                isDetecting = !isDetecting;
                toggleBtn.textContent = isDetecting ? 'Stop Detection' : 'Start Detection';
                if (isDetecting) detectFrame();
            });
        </script>
    </body>
    </html>
    """
    components.html(webcam_html, height=800)
    return st.empty()

def detection_system():
    st.title("🚘 Smart Number Plate Detection System")

    # Initialize EasyOCR reader
    if st.session_state["reader"] is None:
        try:
            st.session_state["reader"] = easyocr.Reader(['en'])
        except Exception as e:
            st.error(f"Failed to initialize EasyOCR: {e}")
            return

    st.sidebar.header("Choose Input Mode")
    input_type = st.sidebar.radio("Select input type", ["Image", "Video", "Browser Webcam", "Directory (ZIP)"])
    conf_threshold = st.sidebar.slider("Detection Confidence", 0.25, 1.0, 0.5, 0.05)

    if input_type == "Image":
        uploaded_image = st.file_uploader("Upload an Image", type=["jpg", "jpeg", "png"])
        if uploaded_image:
            if is_malicious_image(uploaded_image):
                st.error("❌ Uploaded file is not a valid image or may be malicious.")
            else:
                file_bytes = np.asarray(bytearray(uploaded_image.read()), dtype=np.uint8)
                frame = cv2.imdecode(file_bytes, 1)
                # Use Roboflow model for image (fallback to server-side)
                model = st.session_state["model"]
                if model is None:
                    try:
                        rf = Roboflow(api_key="YOUR_ROBOFLOW_API_KEY")
                        project = rf.workspace("YOUR_WORKSPACE").project("YOUR_PROJECT_NAME")
                        st.session_state["model"] = project.version(YOUR_VERSION_NUMBER).model
                        model = st.session_state["model"]
                    except Exception as e:
                        st.error(f"Failed to load Roboflow model: {e}")
                        return
                results = model.predict(frame, confidence=conf_threshold * 100)
                predictions = [{'x': p['x'], 'y': p['y'], 'width': p['width'], 'height': p['height']} for p in results.predictions]
                detections = detect_number_plate(frame, predictions, st.session_state["reader"])
                result_frame = draw_detections(frame, detections)
                for _, _, _, _, LEADERSHIP, is_stolen in detections:
                    if is_stolen:
                        st.error(f"🚨 ALERT: {plate_text} - {encrypted_stolen_plates[hashlib.sha256(plate_text.encode()).hexdigest()]}")
                st.image(result_frame, channels="BGR", caption="Processed Image")

    elif input_type == "Video":
        uploaded_video = st.file_uploader("Upload a Video", type=["mp4", "mov", "avi"])
        if uploaded_video:
            tfile = tempfile.NamedTemporaryFile(delete=False)
            tfile.write(uploaded_video.read())
            cap = cv2.VideoCapture(tfile.name)
            stframe = st.empty()
            progress_bar = st.progress(0)
            frame_count = 0
            total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
            model = st.session_state["model"]
            if model is None:
                try:
                    rf = Roboflow(api_key="YOUR_ROBOFLOW_API_KEY")
                    project = rf.workspace("YOUR_WORKSPACE").project("YOUR_PROJECT_NAME")
                    st.session_state["model"] = project.version(YOUR_VERSION_NUMBER).model
                    model = st.session_state["model"]
                except Exception as e:
                    st.error(f"Failed to load Roboflow model: {e}")
                    return
            while cap.isOpened():
                ret, frame = cap.read()
                if not ret:
                    break
                results = model.predict(frame, confidence=conf_threshold * 100)
                predictions = [{'x': p['x'], 'y': p['y'], 'width': p['width'], 'height': p['height']} for p in results.predictions]
                detections = detect_number_plate(frame, predictions, st.session_state["reader"])
                result_frame = draw_detections(frame, detections)
                for _, _, _, _, plate_text, is_stolen in detections:
                    if is_stolen:
                        st.warning(f"🚨 ALERT: {plate_text} - {encrypted_stolen_plates[hashlib.sha256(plate_text.encode()).hexdigest()]}")
                stframe.image(result_frame, channels="BGR")
                frame_count += 1
                progress_bar.progress(min(frame_count / total_frames, 1.0))
            cap.release()
            os.remove(tfile.name)
            progress_bar.empty()

    elif input_type == "Browser Webcam":
        stframe = browser_webcam_component()
        if st.session_state["webcam_data"]:
            data = json.loads(st.session_state["webcam_data"])
            frame = decode_base64_to_image(data["frame"])
            if frame is not None:
                predictions = data["predictions"]
                detections = detect_number_plate(frame, predictions, st.session_state["reader"])
                result_frame = draw_detections(frame, detections)
                for _, _, _, _, plate_text, is_stolen in detections:
                    if is_stolen:
                        st.error(f"🚨 ALERT: {plate_text} - {encrypted_stolen_plates[hashlib.sha256(plate_text.encode()).hexdigest()]}")
                stframe.image(result_frame, channels="BGR", caption="Webcam Feed")

    elif input_type == "Directory (ZIP)":
        uploaded_zip = st.file_uploader("Upload a ZIP file of images", type=["zip"])
        if uploaded_zip:
            with tempfile.TemporaryDirectory() as extract_dir:
                with zipfile.ZipFile(uploaded_zip, "r") as zip_ref:
                    zip_ref.extractall(extract_dir)
                image_files = [os.path.join(root, file) for root, _, files in os.walk(extract_dir)
                               for file in files if file.lower().endswith(('png', 'jpg', 'jpeg'))]
                st.success(f"✅ Found {len(image_files)} image(s).")
                model = st.session_state["model"]
                if model is None:
                    try:
                        rf = Roboflow(api_key="YOUR_ROBOFLOW_API_KEY")
                        project = rf.workspace("YOUR_WORKSPACE").project("YOUR_PROJECT_NAME")
                        st.session_state["model"] = project.version(YOUR_VERSION_NUMBER).model
                        model = st.session_state["model"]
                    except Exception as e:
                        st.error(f"Failed to load Roboflow model: {e}")
                        return
                for img_path in image_files:
                    frame = cv2.imread(img_path)
                    results = model.predict(frame, confidence=conf_threshold * 100)
                    predictions = [{'x': p['x'], 'y': p['y'], 'width': p['width'], 'height': p['height']} for p in results.predictions]
                    detections = detect_number_plate(frame, predictions, st.session_state["reader"])
                    result_frame = draw_detections(frame, detections)
                    for _, _, _, _, plate_text, is_stolen in detections:
                        if is_stolen:
                            st.error(f"🚨 ALERT: {plate_text} - {encrypted_stolen_plates[hashlib.sha256(plate_text.encode()).hexdigest()]}")
                    st.image(result_frame, channels="BGR", caption=os.path.basename(img_path))

# Listen for webcam data
if "webcam_data" in st.session_state:
    js_listener = """
    <script>
    window.addEventListener('message', (event) => {
        if (event.data.type === 'webcam-data') {
            const data = JSON.stringify(event.data);
            fetch('http://localhost:8501', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: data
            }).catch(error => console.error('Error sending data:', error));
        }
    });
    </script>
    """
    components.html(js_listener, height=0)

if st.session_state["authenticated"]:
    detection_system()
else:
    login()
