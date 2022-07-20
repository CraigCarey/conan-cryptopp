```bash
mkdir bld && cd bld
conan install .. -s build_type=Debug --build=missing
cmake ..
make
```
