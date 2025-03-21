FROM python:3.9-slim
 
ENV PYTHONUNBUFFERED 1
 
# Set the working directory in the container
WORKDIR /commander
 
# Copy the local directory contents into the container's directory
COPY . /commander
 
# Install the necessary dependencies
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install --no-cache-dir -e .
 
# Set up an entrypoint
ENTRYPOINT ["python3", "keeper.py"]