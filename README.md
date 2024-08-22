# fcrypt - A simple file encryption CLI
fcrypt is a simple CLI for file encryption using passwords written in C. 

# Building
fcrypt uses CMake as its build system. The project can be built in the standard way, i.e
```sh
$ mkdir build
$ cd build
$ cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=on -G Ninja ..
$ ninja
$ ./fcrypt --version
```

The `patch` command is needed to build on Windows.

It's highly recommended to use ThinLTO (`DCMAKE_INTERPROCEDURAL_OPTIMIZATION=on`) during the build as this greatly reduces the executable size. 

There are a couple variables used during the build, listed here:

| Variable          | Default | Description                                 |
|-------------------|---------|---------------------------------------------|
| `USE_SANITIZERS`  | `off`    | Enables the use of ASan and UBSan.          |
| `BUILD_X86_64_V3` | `off`   | Enables x86-64-v3 optimizations for Argon2. |


# Usage
## Encrypting a file
```sh
$ fcrypt -p "my very secure password" -i somefile.txt -o somefile.txt.enc
```

## Decrypting a file
```sh
fcrypt -d -p "my very secure password" -i somefile.txt.enc -o somefile.txt.dec
```

# Details   

fcrypt uses AES-256-GCM or ChaCha20-Poly1305 for the encryption itself, and argon2 for key derivation. The format is (informally) described below.   
   
The file starts with the full chunk of encrypted data (from the original file). Then, the following data is appended in this order. 

- File format magic (8 bytes)
- AEAD authentication tag (16 bytes)
- Argon2 Salt (32 bytes)
- AEAD IV (12 bytes)

# Future plans
- Rewrite in Rust
- Add standalone key-generation (generate and wrap key with a password)
- Add more features, like signing/verifying and hashing
- Add public-key encryption support
- Allow multiple keys to decrypt a file
