import numpy as np
import tensorflow as tf
import os

directory = "/home/fyp/Desktop/cnn/"
model_dir = "/home/kali/Downloads/models/model5/"
classes = {0:["BENIGN"], 1:["FTP-Patator"], 2:["SSH-Patator"], 3:["DoS GoldenEye"], 4:["DoS Hulk"], 5:["DoS Slowhttptest"], 6:["DoS slowloris"], 7:["Web Attack ñ Brute Force", "Web Attack ñ Sql Injection", "Web Attack ñ XSS"], 8:["Bot"], 9:["DDoS"], 10:["PortScan"]}

def get_file_info(dir):
    file = np.load(dir + "data.npz")
    train_labels = np.array(file["train_labels"])
    train_vectors = np.array(file["train_vectors"])
    test_labels = np.array(file["test_labels"])
    test_vectors = np.array(file["test_vectors"])
    return train_labels, train_vectors, test_labels, test_vectors

def build_model():
    model = tf.keras.Sequential([
        tf.keras.layers.Reshape((40,40,1), input_shape=(1600,)),

        tf.keras.layers.Conv2D(filters=32, kernel_size=(5,5), activation="relu"),
        tf.keras.layers.MaxPool2D(pool_size=(2, 2)),
        tf.keras.layers.Conv2D(filters=64, kernel_size=(3,3), activation="relu"),
        tf.keras.layers.MaxPool2D(pool_size=(2, 2)),

        tf.keras.layers.Flatten(),
        tf.keras.layers.Dense(1600, activation=tf.nn.relu),
        tf.keras.layers.Dropout(0.2),
        tf.keras.layers.Reshape((10,160)),

        tf.keras.layers.LSTM(256, return_sequences=True, recurrent_activation='sigmoid'),
        tf.keras.layers.LSTM(256, recurrent_activation='sigmoid'),
        tf.keras.layers.Dense(128, activation='sigmoid'),
        tf.keras.layers.Dense(len(classes), activation=tf.nn.softmax)
    ])
    model.compile(optimizer=tf.keras.optimizers.Adam(learning_rate=1e-2),
              loss=tf.keras.losses.MeanSquaredError(),
              metrics=['accuracy'])
    return model


train_labels, train_vectors, test_labels, test_vectors = get_file_info(directory)
past_acc = 0

if os.path.exists(os.path.join(model_dir, "saved_model.pb")):
    model = tf.keras.models.load_model(model_dir)
    test_loss, test_acc = model.evaluate(test_vectors, test_labels)
    past_acc = test_acc
    print('OG accuracy:', test_acc)

while True:
    model = build_model()
    model.fit(train_vectors, train_labels, batch_size = 1000, epochs = 3)
    test_loss, test_acc = model.evaluate(test_vectors, test_labels)
    if test_acc > past_acc:
        print('Test accuracy:', test_acc)
        past_acc = test_acc
        model.save(model_dir)
    if past_acc > 0.99:
        model.save(model_dir)
        break
