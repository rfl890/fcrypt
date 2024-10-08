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

Currently, the `patch` command is needed to build. You won't need it when libressl updates to `v3.9.3`.

It's highly recommended to use ThinLTO (`DCMAKE_INTERPROCEDURAL_OPTIMIZATION=on`) during the build as this greatly reduces the executable size. 

There are a couple variables used during the build, listed here:

| Variable          | Default | Description                                 |
|-------------------|---------|---------------------------------------------|
| `USE_SANITIZERS`  | `off`    | Enables the use of ASan and UBSan.          |
| `BUILD_X86_64_V3` | `off`   | Enables x86-64-v3 optimizations for Argon2. |


# Testing
Tests are written in Lua. It's built automatically with the project.
To run tests:
```sh
$ ctest
```

# Usage
## Encrypting a file
```sh
$ fcrypt -p "my very secure password" -i somefile.txt -o somefile.txt.enc
```

## Decrypting a file
```sh
$ fcrypt -dp "my very secure password" -i somefile.txt.enc -o somefile.txt.dec
```

# Details   

fcrypt uses AES-256-CTR or ChaCha20 for the encryption itself, Blake3 for authentication, and argon2 for key derivation. The format is (informally) described below.   

First, an 8-byte magic header is written to the file. Then, the encrypted file data. Finally, 
the Argon2 salt (32 bytes) and Blake3 MAC (32 bytes) is written to the end of the file.

# Future plans
- Add standalone key-generation (generate and wrap key with a password)
- Add more features, like signing/verifying and hashing
- Add public-key encryption support
- Allow multiple keys to decrypt a file
- Rewrite in Rust
