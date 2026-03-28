import os
os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = r"C:\Users\LENOVO\AppData\Roaming\gcloud\application_default_credentials.json"

from google import genai
from google.genai.types import HttpOptions

client = genai.Client(
    http_options=HttpOptions(api_version="v1beta1"),
    vertexai=True,
    project="project-104d6baa-6079-4f58-9d8",
    location="us-central1",
)

response = client.models.generate_content(
    model="gemini-2.5-pro",
    contents="Say hello",
)

print(response.text)