import cv2
import face_recognition

# Load the image of the known person
known_image = cv2.imread("path/to/known_face.jpg")
known_encoding = face_recognition.face_encodings(known_image)[0]  # Assuming only one face

# Start video capture
video_capture = cv2.VideoCapture(0)  # Use 0 for default webcam

while True:
    # Capture frame-by-frame
    ret, frame = video_capture.read()

    # Convert frame to RGB for face_recognition
    rgb_frame = frame[:, :, ::-1]

    # Find all faces in the current frame
    face_locations = face_recognition.face_locations(rgb_frame)

    # Encode faces in the current frame
    face_encodings = face_recognition.face_encodings(rgb_frame, face_locations)

    # Loop through each face in the current frame
    for (top, right, bottom, left), face_encoding in zip(face_locations, face_encodings):
        # Compare encoded face with the known face
        match = face_recognition.compare_faces([known_encoding], face_encoding)

        # Draw rectangle around detected face with label
        if match[0]:  # True if there's a match
            cv2.rectangle(frame, (left, top), (right, bottom), (0, 0, 255), 2)
            cv2.putText(frame, "Known Person", (left + 6, bottom - 6), cv2.FONT_HERSHEY_DUPLEX,
                        1.0, (255, 255, 255), 1)

    # Display the resulting frame
    cv2.imshow('Video', frame)

    # Exit loop if 'q' key is pressed
    if cv2.waitKey(1) & 0xFF == ord('q'):
        break

# Release capture and close windows
video_capture.release()
cv2.destroyAllWindows()

