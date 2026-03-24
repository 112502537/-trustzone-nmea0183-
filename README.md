# -trustzone-nmea0183-
利用trustzone的保護機制，將明文傳送的nmea0183訊息進行數位簽章，再傳送端的ta簽章完畢後，由ca傳送給另一台主機，並由接收端的ca轉傳給ta驗證，確認是否可信。全程在VirtualBox虛擬機中進行，環境為Ubuntu20.04。
