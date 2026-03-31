# PHÂN TÍCH KỸ THUẬT: GIẢI MÃ HỆ THỐNG 9 LFSR

### 1. Mô hình hóa hệ phương trình Tuyến tính
Với việc LFSR 3 có chu kì ngắn là 63, thì ta sẽ cho LFSR 3 và 4 vào chung 1 bộ 63 biến. Tổng quan chúng ta có 1 hệ gồm 640 phương trình với 374 ẩn số bao gồm:

* **32 ẩn** của hệ LFSR 1 (do tính chất tuyến tính)
* **24 ẩn** của hệ LFSR 2 (do tính chất tuyến tính hóa)
* **63 ẩn** của hệ LFSR 3 và 4 (tức là bit $w \oplus v$ có chu kì là 63)
* **255 ẩn** của hệ LFSR 5, 6, 7 (tức là bit $u$ có chu kì 255)

Với mỗi clock $i$, đặt vế phải của phương trình là $a_i$ ($a_i = y \oplus z \oplus w \oplus v \oplus u$), ta sẽ có 1 phương trình của hệ là:
$$p_1x_1 + \dots + p_{32}x_{32} + p_{33}x_{33} + \dots + p_{374}x_{374} = a_i$$

Với:
* $p_1x_1 + \dots + p_{32}x_{32}$ là feedforward của LFSR 1 tại clock $i$ (cơ chế như LFSR thường => có thể gen 640 biểu thức tuyến tính qua từng clock).
* $p_{33}x_{33} + \dots + p_{56}x_{56}$ là feedforward của LFSR 2 tại clock $i$ (biết các feedback + biểu thức tuyến tính => có thể gen 640 biểu thức tuyến tính qua từng clock).
* $p_{57}x_{57} + \dots + p_{119}x_{119}$ là bit $w \oplus v$ của LFSR 3 và 4 tại clock $i$. Đối với phần này, ta chỉ cần đặt $p_j = 1$ nếu $j = 57 + (i \pmod{63})$.
* $p_{120}x_{120} + \dots + p_{374}x_{374}$ là bit $u$ của LFSR 5, 6, 7 tại clock $i$. Đối với phần này, ta chỉ cần đặt $p_j = 1$ nếu $j = 120 + (i \pmod{255})$.

### 2. Chiến lược xử lý thành phần Phi tuyến
Với hệ $640 \times 374$ này, với mỗi bộ vế phải là $(a_1, a_2, \dots, a_{640})$ đưa vào thì xác suất để hệ có nghiệm là rất thấp ($1/2^{266}$), tức là gần như chỉ khi bộ $a_1, a_2, \dots, a_{640}$ đúng thì mới ra nghiệm. 

Vậy nên chúng ta chỉ cần đoán 2 initial state của LFSR 0 và LFSR 8 còn lại, gen stream bit $x \oplus s$ của 2 bộ đó qua 640 clock và XOR với keystream sinh ra stream $a_1, \dots, a_{640}$. Nếu hệ có nghiệm thì đó chính là bộ LFSR 0 và LFSR 8 đúng (tức là chỉ khi đoán đúng 2 LFSR còn lại thì hệ mới có nghiệm được).

LFSR 0 có 14 bit state, LFSR 8 có 10 bit state => để đoán 24 bit sẽ có 16 triệu trường hợp => 16 triệu bộ $a_i$, 16 triệu lần giải hệ => hoàn toàn có thể giải ra.

### 3. Kỹ thuật Meet-in-the-Middle (MITM)
Chiến lược brute force toàn bộ 16 triệu case tốn nhiều thời gian. Để tối ưu hóa, ta sử dụng kỹ thuật **Meet-in-the-Middle**: 
Với $K$ là keystream (640), $M$ là ma trận của hệ ($640 \times 374$), $X$ là vector nghiệm (374), $L_0$ là stream của LFSR 0, $L_8$ là stream của LFSR 8, ta có:
$$K = (M \cdot X) \oplus (L_0 \oplus L_8) \quad (1)$$

Trong toán học, với một ma trận $M$ cho trước, luôn tồn tại ma trận $H$ sao cho $H \cdot M = 0$. Nhân 2 vế của (1) với $H$:
$$H \cdot K = H \cdot L_0 \oplus H \cdot L_8 \iff H \cdot L_0 = H \cdot K \oplus H \cdot L_8 \quad (2)$$

Ta chắc chắn rằng chỉ khi $L_0$ và $L_8$ đúng thì biểu thức (2) mới thỏa mãn. Vậy nên ta chỉ cần:
1. Tạo 1 hash map, duyệt qua $2^{14}$ case của LFSR 0 và lưu vào bảng hash các giá trị $H \cdot L_0$.
2. Sau đó brute qua $2^{10}$ case của LFSR 8, với mỗi case tính $H \cdot K \oplus H \cdot L_8$ và kiểm tra xem có giá trị đó trong hash table không. Nếu có thì đó chính là 2 giá trị $L_0$ và $L_8$ cần tìm.

Việc dùng bảng hash thì mỗi lần tìm kiếm chỉ tốn $O(1)$, nhanh hơn rất nhiều so với việc brute cả 24 bit cùng lúc.

### 4. Giai đoạn Giải mã (Decryption)
Khi đã có initial state của LFSR 0 và LFSR 8, ta chỉ cần gen ra bộ $(a_1, a_2, \dots, a_{640})$ của hệ phương trình và giải hệ đó bằng phương pháp khử Gauss. Khi đó với bộ nghiệm có được:
* Với bit $u$ và $w \oplus v$ theo chu kì, ta chỉ cần gen tiếp các bit đó theo công thức modulo.
* Với LFSR 1 và 2, các nghiệm tương ứng chính là initial state của 2 hệ đó, chỉ cần gen tiếp stream của 2 hệ này.
=> Ta đã có thể gen toàn bộ keystream của hệ 9 LFSR và decrypt được phần token.