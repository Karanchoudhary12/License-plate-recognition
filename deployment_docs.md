
# 📄 Deployment Documentation for Moving Vehicle Registration Plate Detection
**Project Name:** Moving Vehicle Registration Plate Detection 
**Deployed on:** [Streamlit Cloud](https://share.streamlit.io)

---

## 📌 Deployment Steps

1. **Create a Streamlit Cloud Account**
   - Visit [https://streamlit.io/cloud](https://streamlit.io/cloud) and sign up or log in.

2. **Push Project to GitHub**
   - Ensure your complete project (including `requirements.txt`, `cloud/deployment_docs.md`, YOLO model weights like `yolov8n.pt`, and all your Python files) is pushed to a public or private GitHub repository.

3. **Add a `requirements.txt`**
   - List all necessary Python dependencies for your app. Example:
     ```
     streamlit
     opencv-python
     numpy
     easyocr
     ultralytics
     hashlib
     ```

4. **Create a New App on Streamlit Cloud**
   - Go to [Streamlit Cloud](https://streamlit.io/cloud)
   - Click **New app**
   - Choose your GitHub repo, select the branch (e.g., `main`), and set the `main file path` (e.g., `app.py`)

5. **Deploy**
   - Click **Deploy**. The app will build and launch automatically.
   - Note: YOLO model files like `yolov8n.pt` should either be uploaded to your repo (if small) or hosted at an accessible URL with appropriate download code in your app.

---

## 📁 Project Structure

```
Moving Vehicle Registration Plate Detection/
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

## 📌 Accessing the Deployed App

Once deployed, you’ll receive a shareable link like:

`https://<your-streamlit-username>.streamlit.app`


## 📌 Notes

- **Login credentials** are hardcoded for demo purposes. Replace or secure them via environment variables or a secure authentication service for production use.
- **YOLO model size:** If your model file is too large for GitHub or Streamlit Cloud, consider hosting it externally and downloading it during runtime.
- **EasyOCR language support** can be extended by adding language codes in `easyocr.Reader(['en'])`.
