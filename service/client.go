package service

func MakeSSHKeyPair(pubKeyPath, privateKeyPath string) error {
	/*
		privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		if err != nil {
			return err
		}

		// generate and write private key as PEM
		privateKeyFile, err := os.Create(privateKeyPath)
		defer privateKeyFile.Close()
		if err != nil {
			return err
		}
		privateKeyPEM := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}
		if err := pem.Encode(privateKeyFile, privateKeyPEM); err != nil {
			return err
		}

		// generate and write public key
		pub, err := ssh.NewPublicKey(&privateKey.PublicKey)
		if err != nil {
			return err
		}
		return ioutil.WriteFile(pubKeyPath, ssh.MarshalAuthorizedKey(pub), 0655)
	*/
	return nil
}
