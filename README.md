
# 🚘 Moving Vehicle Registration Plate Detection

A Streamlit-powered intelligent number plate detection system using YOLOv8 and EasyOCR. Detects number plates from images, videos, webcam, and ZIP directories, with integrated stolen vehicle alerts via encrypted hash lookups.

---

## 📌 Features

- 🔐 **Login Authentication** to restrict system access.
- 📸 Detect number plates from:
  - Uploaded images
  - Uploaded videos
  - Live webcam feed
  - Bulk images via ZIP upload
- 📖 Extracts plate numbers using **EasyOCR**
- 🚨 Checks against an **encrypted stolen plates database**
- 📝 Real-time alerts for stolen/missing vehicles
- 📊 Adjustable detection confidence via sidebar slider
- 📦 Simple deployment on **Streamlit Cloud**

---

## 📁 Project Structure

```
smart-number-plate-detection/
│
├── app.py
├── yolov8n.pt
├── requirements.txt
├── cloud/
│   └── deployment_docs.md
├── README.md
└── other dependency files...
```

---

## 🚀 Installation & Run Locally

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/number-plate-detection.git
   cd number-plate-detection
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Run the Streamlit app:
   ```bash
   streamlit run app.py
   ```

---

## 🌐 Deployed App

[Access Live Application](https://license-plate-recognition-2tucufhdifnaomap8itlvt.streamlit.app/)

---

## ⚠️ Notes

- Replace hardcoded login credentials in `app.py` for production use.
- Ensure the YOLO model file `yolov8n.pt` is present in the project directory.
- Customize EasyOCR supported languages if needed.

---

## 📚 Dependencies

- Streamlit
- OpenCV-Python
- NumPy
- EasyOCR
- Ultralytics (YOLOv8)
- hashlib


