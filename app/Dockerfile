# Use the official Python image based on Alpine Linux
FROM python:alpine

# Set the working directory inside the container to /app
WORKDIR /app

# Copy requirements file for dependencies
COPY requirements.txt .

# Install dependencies from requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the Python script into the working directory
COPY main.py /app

# Run the Python script when the container starts
CMD ["python", "main.py"]