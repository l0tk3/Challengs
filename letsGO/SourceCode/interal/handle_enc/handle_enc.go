package handle_enc

func Enc1(s, key *[]byte, length int) {
	j := byte(0)
	k := make([]byte, 256)
	tmp := byte(0)
	for i := 0; i < 256; i++ {
		(*s)[i] = byte(i)
		k[i] = (*key)[i%length]
	}
	for i := 0; i < 256; i++ {
		j = j + (*s)[i] + k[i]
		tmp = (*s)[i]
		(*s)[i] = (*s)[j]
		(*s)[j] = tmp
	}
}
func Enc2(s, data *[]byte, length int) {
	i := byte(0)
	j := byte(0)
	var tmp byte
	var t byte
	for k := 0; k < length; k++ {
		i = i + 1
		j = j + (*s)[i]
		tmp = (*s)[i]
		(*s)[i] = (*s)[j]
		(*s)[j] = tmp
		t = (*s)[i] + (*s)[j]
		(*data)[k] ^= (*s)[t]
	}
}
