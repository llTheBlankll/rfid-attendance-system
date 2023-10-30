#include <MFRC522.h>
#include <SPI.h>
#include <ESP8266HTTPClient.h>
#include <ESP8266WiFi.h>
#include <ArduinoWebsockets.h>
#include <cstring>

// Use this as client when you're requesting data from an HTTPS server.
// #include <ESP8266WebServerSecure.h>

// * RFID START CONFIGURATION
#define RESET_PIN 5
#define SS_PIN 10
MFRC522 rfid(SS_PIN, RESET_PIN);
MFRC522::MIFARE_Key key;
// * RFID CONFIGURATION END

// * ESP8266 WIFI CONFIGURATION
#define ssid        "PLDTHOMEFIBR9u7w4"
#define pass        "PLDTWIFIkr39h"
#define websocket_server_in     "ws://localhost:8080/websocket/scanner/in"
#define websocket_server_out    "ws://localhost:8080/websocket/scanner/out"

// Set websocket client.
websockets::WebsocketsClient ws_client;
// * ESP8266 WIFI CONFIGURATION END

void setup()
{
    // Set Baud Rate 9600
    Serial.begin(9600);

    // If there is no Serial, do nothing.
    while (!Serial);

    // Begin SPI and initialize RFID.
    SPI.begin();
    rfid.PCD_Init();
    Serial.println("RFID Card was initialized.");

    // Set default key for RFID.
    for (int i = 0; i < MFRC522::MF_KEY_SIZE; i++)
    {
        key.keyByte[i] = 0xFF; // 6 bytes 0xFF as key
    }

    // Configure WiFi Connection
    WiFi.mode(WIFI_STA); // Set WiFi as Stationary.
    WiFi.begin(ssid, pass);

    // Wait for connection
    int retries = 0;
    int max_retries = 15;
    while (WiFi.status() != WL_CONNECTED && retries <= max_retries)
    {
        Serial.println("Connecting");
        delay(500);
        Serial.print(".");
    }

    // Print Connection Status
    if (WiFi.status() == WL_CONNECTED)
    {
        Serial.println("Connection Successful!");
        Serial.println("Successfully connected to :");
        Serial.print(ssid);
        Serial.println();
        Serial.println("IP address: ");
        Serial.println("Connection Strength: ");
        Serial.println(WiFi.RSSI());
        Serial.print(WiFi.localIP());
    }

    // Set delay for stability and gives time for the microcontroller to initialize.
    
    // * Websocket Configuration
    // * By default, it will connect to the server at "ws://localhost:8080/websocket/scanner/in" where student attendance will be stored as they arrive.  
    ws_client.onMessage(on_message_callback);
    ws_client.onEvent(on_events_callback);

    // Connect to a server
    ws_client.connect(websocket_server_in);

    delay(100);
}

void loop()
{
    // ! Check for messages and events
    ws_client.poll();

    // Check if the connection was lost.
    if (WiFi.status() == WL_DISCONNECTED)
    {
        WiFi.reconnect();
    }

    if (rfid.PICC_IsNewCardPresent() && rfid.PICC_ReadCardSerial())
    {
        Serial.println();
        Serial.println("RFID Card Detected");
    }

    // Read Block 1
    byte hashFirstPart = 4;
    byte hashSecondPart = 5;
    MFRC522::StatusCode status = rfid.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, hashFirstPart, &key, &(rfid.uid));
    byte buffer[18];
    byte bufferSize = sizeof(buffer);
    byte hashBytes[32];

    if (status == MFRC522::STATUS_OK)
    {
        status = rfid.MIFARE_Read(hashFirstPart, buffer, &bufferSize);
        // Read the first part of the HASH 16 bytes
        if (status == MFRC522::STATUS_OK)
        {
            for (int byte = 0; byte < bufferSize; byte++)
            {
                hashBytes[byte] = buffer[byte];
            }
            // Serial.println("First part of the HASH: ");
        }
        dump_byte_array(hashBytes, 16);

        // Empty the buffer.
        memset(buffer, 0, sizeof(buffer));
        // Serial.println("\nEmptying the buffer");
        status = rfid.MIFARE_Read(hashSecondPart, buffer, &bufferSize);

        if (status == MFRC522::STATUS_OK)
        {
            for (int byte = 0; byte < bufferSize; byte++)
            {
                hashBytes[byte + 16] = buffer[byte];
            }
        }

        // Print the hash
        String hashString = hexStringToString(byteArrayToString(hashBytes, 32));

        // Send request to the server.
        addAttendance(hashString);
    }

    rfid.PICC_HaltA();
    rfid.PCD_StopCrypto1();
    delay(50);
}

void on_message_callback(websockets::WebsocketsMessage message) {
    String status = message.data();
    if (status == "true") {
        Serial.println("Attendance Successful");
        return;
    }

    Serial.println("No Attendance");
}

void on_events_callback(websockets::WebsocketsEvent event, String data) {
    if (event == websockets::WebsocketsEvent::ConnectionOpened) {
        Serial.println("Connnection Opened");
    } else if (event == websockets::WebsocketsEvent::ConnectionClosed) {
        Serial.println("Connnection Closed");
    } else if (event == websockets::WebsocketsEvent::GotPing) {
        Serial.println("Got a Ping!");
    } else if (event == websockets::WebsocketsEvent::GotPong) {
        Serial.println("Got a Pong!");
    }
}

/**
 * Add attendance for a student.
 *
 * @param hashedLRN The hashed Local Registration Number of the student.
 *
 * @return True if the request was success, false otherwise.
 *
 * @throws ErrorType If there is an error while adding the attendance.
 */
boolean addAttendance(String hashedLRN)
{
    // Check if empty
    if (hashedLRN == "")
    {
        return false;
    }

    // Send request to the server.
    ws_client.send(hashedLRN);

    return true;
}

String hexStringToString(const String &hexString)
{
    String result = "";
    int strLen = hexString.length();
    for (int i = 0; i < strLen; i += 2)
    {
        String hexByte = hexString.substring(i, i + 2);
        char charByte = (char)strtol(hexByte.c_str(), NULL, 16);
        result += charByte;
    }
    return result;
}

void dump_byte_array(byte *buffer, byte bufferSize)
{
    for (byte i = 0; i < bufferSize; i++)
    {
        Serial.print(buffer[i] < 0x10 ? " 0" : " ");
        Serial.print(buffer[i], HEX);
    }
}

String byteArrayToString(byte *array, int size)
{
    String str = "";
    for (int i = 0; i < size; i++)
    {
        str += String(array[i], HEX);
    }

    return str;
}