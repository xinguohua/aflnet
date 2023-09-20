# AFLNet: A Greybox Fuzzer for Network Protocols
AFLNet is a greybox fuzzer for protocol implementations. Unlike existing protocol fuzzers, it takes a mutational approach and uses state-feedback, in addition to code-coverage feedback, to guide the fuzzing process. AFLNet is seeded with a corpus of recorded message exchanges between the server and an actual client. No protocol specification or message grammars are required. It acts as a client and replays variations of the original sequence of messages sent to the server and retains those variations that were effective at increasing the coverage of the code or state space. To identify the server states that are exercised by a message sequence, AFLNet uses the server’s response codes. From this feedback, AFLNet identifies progressive regions in the state space, and systematically steers towards such regions.

AFLNet 是一个用于协议实现的灰盒模糊器。 与现有的协议模糊器不同，它采用突变方法，除了代码覆盖率反馈之外，还使用状态反馈来指导模糊过程。 AFLNet 的种子是服务器和实际客户端之间记录的消息交换的语料库。 不需要协议规范或消息语法。 它充当客户端，重放发送到服务器的原始消息序列的变体，并保留那些有效增加代码或状态空间覆盖范围的变体。 为了识别消息序列所执行的服务器状态，AFLNet 使用服务器的响应代码。 根据此反馈，AFLNet 识别状态空间中的进步区域，并系统地转向这些区域。
# Licences

AFLNet is licensed under [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0).

AFLNet is an extension of [American Fuzzy Lop](http://lcamtuf.coredump.cx/afl/) written and maintained by Michał Zalewski <<lcamtuf@google.com>>. For details on American Fuzzy Lop, we refer to [README-AFL.md](README-AFL.md).

* **AFL**: [Copyright](https://github.com/aflsmart/aflsmart/blob/master/docs/README) 2013, 2014, 2015, 2016 Google Inc. All rights reserved. Released under terms and conditions of [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0).

# Citing AFLNet
AFLNet has been accepted for publication as a Testing Tool paper at the IEEE International Conference on Software Testing, Verification and Validation (ICST) 2020. 

```
@inproceedings{AFLNet,
author={Van{-}Thuan Pham and Marcel B{\"o}hme and Abhik Roychoudhury},
title={AFLNet: A Greybox Fuzzer for Network Protocols},
booktitle={Proceedings of the 13rd IEEE International Conference on Software Testing, Verification and Validation : Testing Tools Track},
year={2020},}
```

# Installation (Tested on Ubuntu 18.04 & 16.04 64-bit)

## Prerequisites

```bash
# Install clang (as required by AFL/AFLNet to enable llvm_mode)
sudo apt-get install clang
# Install graphviz development
sudo apt-get install graphviz-dev libcap-dev
```

## AFLNet

Download AFLNet and compile it. We have tested AFLNet on Ubuntu 18.04 and Ubuntu 16.04 64-bit and it would also work on all environments that support the vanilla AFL and [graphviz](https://graphviz.org).
下载 AFLNet 并编译它。 我们已经在 Ubuntu 18.04 和 Ubuntu 16.04 64 位上测试了 AFLNet，它也适用于支持普通 AFL 和 [graphviz](https://graphviz.org) 的所有环境。

```bash
# First, clone this AFLNet repository to a folder named aflnet
git clone <links to the repository> aflnet
# Then move to the source code folder
cd aflnet
make clean all
cd llvm_mode
# The following make command may not work if llvm-config cannot be found
# To fix this issue, just set the LLVM_CONFIG env. variable to the specific llvm-config version on your machine
# On Ubuntu 18.04, it could be llvm-config-6.0 if you have installed clang using apt-get
make
# Move to AFLNet's parent folder
cd ../..
export AFLNET=$(pwd)/aflnet
export WORKDIR=$(pwd)
```

## Setup PATH environment variables

```bash
export PATH=$PATH:$AFLNET
export AFL_PATH=$AFLNET
```

# Usage

AFLNet adds the following options to AFL. Run ```afl-fuzz --help``` to see all options. Please also see the FAQs section for common questions about these AFLNet's options.

- ***-N netinfo***: server information (e.g., tcp://127.0.0.1/8554)

- ***-P protocol***: application protocol to be tested (e.g., RTSP, FTP, DTLS12, DNS, DICOM, SMTP, SSH, TLS, DAAP-HTTP, SIP)

- ***-D usec***: (optional) waiting time (in microseconds) for the server to complete its initialization 

- ***-e netnsname***: (optional) network namespace name to run the server in

- ***-K*** : (optional) send SIGTERM signal to gracefully terminate the server after consuming all request messages

- ***-E*** : (optional) enable state aware mode

- ***-R*** : (optional) enable region-level mutation operators

- ***-F*** : (optional) enable false negative reduction mode

- ***-c script*** : (optional) name or full path to a script for server cleanup

- ***-q algo***: (optional) state selection algorithm (e.g., 1. RANDOM_SELECTION, 2. ROUND_ROBIN, 3. FAVOR)

- ***-s algo***: (optional) seed selection algorithm (e.g., 1. RANDOM_SELECTION, 2. ROUND_ROBIN, 3. FAVOR)


AFLNet 向 AFL 添加了以下选项。 运行 afl-fuzz --help 以查看所有选项。 另请参阅常见问题解答部分，了解有关这些 AFLNet 选项的常见问题。

-N netinfo：服务器信息（例如，tcp://127.0.0.1/8554）

-P 协议：要测试的应用协议（例如，RTSP、FTP、DTLS12、DNS、DICOM、SMTP、SSH、TLS、DAAP-HTTP、SIP）

-D usec：（可选）服务器完成初始化的等待时间（以微秒为单位）

-e netnsname：（可选）运行服务器的网络命名空间名称

-K ：（可选）在消耗完所有请求消息后发送 SIGTERM 信号以优雅地终止服务器

-E ：（可选）启用状态感知模式

-R ：（可选）启用区域级突变运算符

-F ：（可选）启用假阴性减少模式

-c script ：（可选）用于服务器清理的脚本的名称或完整路径

-q algo：（可选）状态选择算法（例如，1. RANDOM_SELECTION、2. ROUND_ROBIN、3. FAVOR）

-s algo：（可选）种子选择算法（例如，1. RANDOM_SELECTION、2. ROUND_ROBIN、3. FAVOR）

命令示例：

Example command: 
```bash
afl-fuzz -d -i in -o out -N <server info> -x <dictionary file> -P <protocol> -D 10000 -q 3 -s 3 -E -K -R <executable binary and its arguments (e.g., port number)>
```

# Tutorial - Fuzzing Live555 media streaming server
教程 - 模糊 Live555 媒体流服务器

[Live555 Streaming Media](http://live555.com) is a C++ library for multimedia streaming. The library supports open protocols such as RTP/RTCP and RTSP for streaming. It is used internally by widely-used media players such as [VLC](https://videolan.org) and [MPlayer](http://mplayerhq.hu) and some security cameras & network video recorders (e.g., [DLink D-View Cameras](http://files.dlink.com.au/products/D-ViewCam/REV_A/Manuals/Manual_v3.51/D-ViewCam_DCS-100_B1_Manual_v3.51(WW).pdf), [Senstar Symphony](http://cdn.aimetis.com/public/Library/Senstar%20Symphony%20User%20Guide%20en-US.pdf), [WISENET Video Recorder](https://www.eos.com.au/pub/media/doc/wisenet/Manuals_QRN-410S,QRN-810S,QRN-1610S_180802_EN.pdf)). In this example, we show how AFLNet can be used to fuzz Live555 and discover bugs in its RTSP server reference implementation (testOnDemandRTSPServer). Similar steps would be followed to fuzz servers implementing other protocols (e.g., FTP, SMTP, SSH).

If you want to run some experiments quickly, please take a look at [ProFuzzBench](https://github.com/profuzzbench/profuzzbench). ProFuzzBench includes a suite of representative open-source network servers for popular protocols (e.g., TLS, SSH, SMTP, FTP, SIP), and tools to automate experimentation.

Live555 Streaming Media 是一个用于多媒体流的 C++ 库。 该库支持 RTP/RTCP 和 RTSP 等开放协议用于流式传输。 它由广泛使用的媒体播放器（例如 VLC 和 MPlayer）以及一些安全摄像机和网络录像机（例如 DLink D-View 摄像机、Senstar Symphony、WISENET 录像机）内部使用。 在此示例中，我们展示了如何使用 AFLNet 来模糊 Live555 并发现其 RTSP 服务器参考实现 (testOnDemandRTSPServer) 中的错误。 对实现其他协议（例如 FTP、SMTP、SSH）的模糊服务器也遵循类似的步骤。

如果您想快速运行一些实验，请看看 ProFuzzBench。 ProFuzzBench 包括一套适用于流行协议（例如 TLS、SSH、SMTP、FTP、SIP）的代表性开源网络服务器以及自动化实验工具。


## Step-0. Server and client compilation & setup
步骤0。 服务器和客户端编译和设置

The newest source code of Live555 can be downloaded as a tarball at [Live555 public page](http://live555.com/liveMedia/public/). There is also [a mirror of the library](https://github.com/rgaufman/live555) on GitHub. In this example, we choose to fuzz an [old version of Live555](https://github.com/rgaufman/live555/commit/ceeb4f462709695b145852de309d8cd25e2dca01) which was commited to the repository on August 28th, 2018. While fuzzing this specific version of Live555, AFLNet exposed four vulnerabilites in Live555, two of which were zero-day. To compile and setup Live555, please use the following commands.

Live555的最新源代码可以在Live555公共页面以tarball形式下载。 GitHub 上还有该库的镜像。 在此示例中，我们选择对 2018 年 8 月 28 日提交到存储库的 Live555 旧版本进行模糊测试。在对 Live555 的特定版本进行模糊测试时，AFLNet 暴露了 Live555 中的四个漏洞，其中两个是零日漏洞。 要编译和设置 Live555，请使用以下命令。

```bash
cd $WORKDIR
# Clone live555 repository
git clone https://github.com/rgaufman/live555.git
# Move to the folder
cd live555
# Checkout the buggy version of Live555
git checkout ceeb4f4
# Apply a patch. See the detailed explanation for the patch below
patch -p1 < $AFLNET/tutorials/live555/ceeb4f4.patch
# Generate Makefile
./genMakefiles linux
# Compile the source
make clean all
```

As you can see from the commands, we apply a patch to make the server effectively fuzzable. In addition to the changes for generating a Makefile which uses afl-clang-fast++ to do the coverage feedback-enabled instrumentation, we make a small change to disable random session ID generation in Live555. In the unmodified version of Live555, it generates a session ID for each connection and the session ID should be included in subsequent requests sent from the connected client. Otherwise, the requests are quickly rejected by the server and this leads to undeterministic paths while fuzzing. Specifically, the same message sequence could exercise different server paths because the session ID is changing. We handle this specific issue by modifing Live555 in such a way that it always generates the same session ID.

Once Live555 source code has been successfully compiled, we should see the server under test (testOnDemandRTSPServer) and the sample RTSP client (testRTSPClient) placed inside the testProgs folder. We can test the server by running the following commands.

正如您从命令中看到的，我们应用了补丁来使服务器有效地可模糊化。 除了生成使用 afl-clang-fast++ 进行覆盖反馈启用检测的 Makefile 的更改之外，我们还进行了一个小更改以禁用 Live555 中的随机会话 ID 生成。 在Live555的未修改版本中，它为每个连接生成一个会话ID，并且该会话ID应该包含在从连接的客户端发送的后续请求中。 否则，请求很快就会被服务器拒绝，这会导致模糊测试时路径不确定。 具体来说，由于会话 ID 正在变化，因此相同的消息序列可能会使用不同的服务器路径。 我们通过修改 Live555 来处理这个特定问题，使其始终生成相同的会话 ID。

成功编译 Live555 源代码后，我们应该看到被测试的服务器 (testOnDemandRTSPServer) 和放置在 testProgs 文件夹中的示例 RTSP 客户端 (testRTSPClient)。 我们可以通过运行以下命令来测试服务器。

```bash
# Move to the folder keeping the RTSP server and client
cd $WORKDIR/live555/testProgs
# Copy sample media source files to the server folder
cp $AFLNET/tutorials/live555/sample_media_sources/*.* ./
# Run the RTSP server on port 8554
./testOnDemandRTSPServer 8554
# Run the sample client on another screen/terminal
./testRTSPClient rtsp://127.0.0.1:8554/wavAudioTest
```

We should see the outputs from the sample client showing that it successfully connects to the server, sends requests and receives responses including streaming data from the server.

我们应该看到示例客户端的输出，显示它成功连接到服务器、发送请求并接收响应，包括来自服务器的流数据。

## Step-1. Prepare message sequences as seed inputs
步骤1。 准备消息序列作为种子输入

AFLNet takes message sequences as seed inputs so we first capture some sample usage scenarios between the sample client (testRTSPClient) and the server under test (SUT). The following steps show how we prepare a seed input for AFLNet based on a usage scenario in which the server streams an audio file in WAV format to the client upon requests. The same steps can be followed to prepare other seed inputs for other media source files (e.g., WebM, MP3).

AFLNet 将消息序列作为种子输入，因此我们首先捕获示例客户端 (testRTSPClient) 和被测服务器 (SUT) 之间的一些示例使用场景。 以下步骤展示了我们如何根据服务器根据请求将 WAV 格式的音频文件流式传输到客户端的使用场景为 AFLNet 准备种子输入。 可以遵循相同的步骤为其他媒体源文件（例如 WebM、MP3）准备其他种子输入。

We first start the server under test
我们首先启动被测服务器

```bash
cd $WORKDIR/live555/testProgs
./testOnDemandRTSPServer 8554
```

After that, we ask [tcpdump data-network packet analyzer](https://www.tcpdump.org) to capture all traffics through the port opened by the server, which is 8554 in this case. Note that you may need to change the network interface that works for your setup using the ```-i``` option.

之后，我们要求 tcpdump 数据网络数据包分析器捕获通过服务器打开的端口（本例中为 8554）的所有流量。 请注意，您可能需要使用 -i 选项更改适合您的设置的网络接口。

```bash
sudo tcpdump -w rtsp.pcap -i lo port 8554
```

Once both the server and tcpdump have been started, we run the sample client

服务器和 tcpdump 启动后，我们运行示例客户端


```bash
cd $WORKDIR/live555/testProgs
./testRTSPClient rtsp://127.0.0.1:8554/wavAudioTest
```

When the client completes its execution, we stop tcpdump. All the requests and responses in the communication between the client and the server should be stored in the specified rtsp.pcap file. Now we use [Wireshark network analyzer](https://wireshark.org) to extract only the requests and use the request sequence as a seed input for AFLNet. Please install Wireshark if you haven't done so.

We first open the PCAP file with Wireshark.

当客户端完成执行后，我们停止 tcpdump。 客户端和服务器之间通信中的所有请求和响应都应该存储在指定的rtsp.pcap文件中。 现在，我们使用 Wireshark 网络分析器仅提取请求，并将请求序列用作 AFLNet 的种子输入。 如果尚未安装 Wireshark，请安装。

我们首先用Wireshark打开PCAP文件。

```bash
wireshark rtsp.pcap
```

This is a screenshot of Wireshark. It shows packets (requests and responses) in multiple rows, one row for one packet.

这是 Wireshark 的屏幕截图。 它以多行形式显示数据包（请求和响应），一行显示一个数据包。

![Analyzing the pcap file with Wireshark](tutorials/live555/images/rtsp_wireshark_1.png)

To extract the request sequence, we first do a right-click and choose Follow->TCP Stream.

要提取请求序列，我们首先右键单击并选择“Follow”->“TCP Stream”。

![Follow TCP Stream](tutorials/live555/images/rtsp_wireshark_2.png)

Wireshark will then display all requests and responses in plain text.

然后，Wireshark 将以纯文本形式显示所有请求和响应。

![View requests and responses in plain text](tutorials/live555/images/rtsp_wireshark_3.png)

As we are only interested in the requests for our purpose, we choose incoming traffic to the SUT-opened port by selecting an option from the bottom-left drop-down list. We choose ```127.0.0.1:57998->127.0.0.1:8554``` in this example which askes Wireshark to display all request messages sent to port 8554.

由于我们只对用于我们目的的请求感兴趣，因此我们通过从左下角下拉列表中选择一个选项来选择 SUT 打开的端口的传入流量。 在此示例中，我们选择 127.0.0.1:57998->127.0.0.1:8554，这要求 Wireshark 显示发送到端口 8554 的所有请求消息。


![View requests in plain text](tutorials/live555/images/rtsp_wireshark_4.png)

Finally, we switch the data mode so that we can see the request sequence in raw (i.e., binary) mode. Click "Save as" and save it to a file, say rtsp_requests_wav.raw.

最后，我们切换数据模式，以便我们可以看到原始（即二进制）模式的请求序列。 单击“另存为”并将其保存到文件中，例如 rtsp_requests_wav.raw。

![View and save requests in raw binary](tutorials/live555/images/rtsp_wireshark_5.png)

The newly saved file rtsp_requests_wav.raw can be fed to AFLNet as a seed input. You can follow the above steps to create other seed inputs for AFLNet, say rtsp_requests_mp3.raw and so on. We have prepared a ready-to-use seed corpus in the tutorials/live555/in-rtsp folder.

新保存的文件 rtsp_requests_wav.raw 可以作为种子输入提供给 AFLNet。 您可以按照上述步骤为 AFLNet 创建其他种子输入，例如 rtsp_requests_mp3.raw 等。 我们在tutorials/live555/in-rtsp文件夹中准备了一个随时可用的种子语料库。

## Step-2. Make modifications to the server code (optional)

Fuzzing network servers is challenging and in several cases, we may need to slightly modify the server under test to make it (effectively and efficiently) fuzzable. For example, this [blog post](http://www.vegardno.net/2017/03/fuzzing-openssh-daemon-using-afl.html) shows several modifications to OpenSSH server to improve the fuzzing performance including disable encryption, disable MAC and so on. In this tutorial, the RTSP server uses the same response code ```200``` for all successful client requests, no matter what actual server state is. So to make fuzzing more effective, we can apply [this simple patch](tutorials/live555/ceeb4f4_states_decomposed.patch) that decomposes the big state 200 into smaller states. It makes the inferred state machine more fine grained and hence AFLNet has more information to guide the state space exploration.

模糊网络服务器具有挑战性，在某些情况下，我们可能需要稍微修改被测服务器以使其（有效且高效）可模糊。 例如，这篇博文展示了对 OpenSSH 服务器的多项修改，以提高模糊测试性能，包括禁用加密、禁用 MAC 等。 在本教程中，RTSP 服务器对所有成功的客户端请求使用相同的响应代码 200，无论实际服务器状态如何。 因此，为了使模糊测试更加有效，我们可以应用这个简单的补丁，将大状态 200 分解为更小的状态。 它使推断的状态机更加细粒度，因此 AFLNet 有更多信息来指导状态空间探索。
## Step-3. Fuzzing

```bash
cd $WORKDIR/live555/testProgs
afl-fuzz -d -i $AFLNET/tutorials/live555/in-rtsp -o out-live555 -N tcp://127.0.0.1/8554 -x $AFLNET/tutorials/live555/rtsp.dict -P RTSP -D 10000 -q 3 -s 3 -E -K -R ./testOnDemandRTSPServer 8554
```

Once AFLNet discovers a bug (e.g., a crash or a hang), a test case containing the message sequence that triggers the bug will be stored in ```replayable-crashes``` or ```replayable-hangs``` folder. In the fuzzing process, AFLNet State Machine Learning component keeps inferring the implmented state machine of the SUT and a .dot file (ipsm.dot) is updated accordingly so that the user can view that file (using a .dot viewer like xdot) to monitor the current progress of AFLNet in terms of protocol inferencing. Please read the AFLNet paper for more information.

一旦 AFLNet 发现错误（例如崩溃或挂起），包含触发错误的消息序列的测试用例将存储在 replayable-crashes 或 replayable-hangs 文件夹中。 在模糊测试过程中，AFLNet 状态机学习组件不断推断 SUT 的实现状态机，并相应更新 .dot 文件 (ipsm.dot)，以便用户可以查看该文件（使用 xdot 等 .dot 查看器） 监控 AFLNet 在协议推理方面的当前进展。 请阅读 AFLNet 论文了解更多信息。
## Step-4. Reproducing the crashes found

AFLNet has an utility (aflnet-replay) which can replay message sequences stored in crash and hang-triggering files (in ```replayable-crashes``` and ```replayable-hangs``` folders). Each file is structured in such a way that aflnet-replay can extract messages based on their size. aflnet-replay takes three parameters which are 1) the path to the test case generated by AFLNet, 2) the network protocol under test, and 3) the server port number. The following commands reproduce a PoC for [CVE-2019-7314](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-7314).

AFLNet 有一个实用程序 (aflnet-replay)，可以重播存储在崩溃和挂起触发文件（在 replayable-crashes 和 replayable-hangs 文件夹中）中的消息序列。 每个文件的结构方式使得 aflnet-replay 可以根据消息的大小提取消息。 aflnet-replay 采用三个参数，即 1）AFLNet 生成的测试用例的路径，2）被测网络协议，以及 3）服务器端口号。 以下命令重现 CVE-2019-7314 的 PoC。
```bash
cd $WORKDIR/live555/testProgs
# Start the server
./testOnDemandRTSPServer 8554
# Run aflnet-replay
aflnet-replay $AFLNET/tutorials/live555/CVE_2019_7314.poc RTSP 8554
```

To get more information about the discovered bug (e.g., crash call stack), you can run the buggy server with [GDB](https://gnu.org/software/gdb) or you can apply the Address Sanitizer-Enabled patch ($AFLNET/tutorials/live555/ceeb4f4_ASAN.patch) and recompile the server before running it. 

要获取有关已发现错误的更多信息（例如，崩溃调用堆栈），您可以使用 GDB 运行有错误的服务器，也可以应用启用 Address Sanitizer 的补丁 ($AFLNET/tutorials/live555/ceeb4f4_ASAN.patch) 并重新编译服务器 在运行之前。
# FAQs

## 1. How do I extend AFLNet?

AFLNet has a modular design that makes it easy to be extended.

AFLNet 采用模块化设计，易于扩展。
### 1.1. How do I add support for another protocol?

If you want to support another protocol, all you need is to follow the steps below.

如果您想支持其他协议，只需按照以下步骤操作即可。

#### Step-1. Implement 2 functions to parse the request and response sequences

步骤1。 实现2个函数来解析请求和响应序列

You can use the available ```extract_requests_*``` and ```extract_response_codes_*``` functions as references. These functions should be declared and implemented in [aflnet.h](aflnet.h) and [aflnet.c](aflnet.c), respectively. Note that, please use the same function parameters.

您可以使用可用的 extract_requests_* 和 extract_response_codes_* 函数作为参考。 这些函数应分别在 aflnet.h 和 aflnet.c 中声明和实现。 请注意，请使用相同的函数参数。

#### Step-2. Update main function to support a new protocol

Please update the code that handles the ```-P``` option in the main function to support a new protocol.

第2步。 更新主要功能以支持新协议
请更新主函数中处理 -P 选项的代码以支持新协议。

### 1.2. How do I implement another search strategy?
1.2. 如何实施另一种搜索策略？

It is quite straightforward. You just need to update the two functions ```choose_target_state``` and ```choose_seed```. The function ```update_scores_and_select_next_state``` may need an extension too. 

这非常简单。 你只需要更新两个函数choose_target_state和choose_seed。 函数 update_scores_and_select_next_state 可能也需要扩展。

## 2. What happens if I don't enable the state-aware mode by adding -E option?

2. 如果我不通过添加 -E 选项来启用状态感知模式，会发生什么情况？

If ```-E``` is not enabled, even though AFLNet still manages the requests' boundaries information so it can still follow the sequence diagram of the protocol -- sending a request, waiting for a response and so on, which is not supported by normal networked-enabled AFL. However, in this setup AFLNet will ignore the responses and it does not construct the state machine from the response codes. As a result, AFLNet cannot use the state machine to guide the exploration.

如果没有启用-E，尽管AFLNet仍然管理请求的边界信息，所以它仍然可以遵循协议的序列图——发送请求、等待响应等等，这是普通网络不支持的—— 启用 AFL。 然而，在此设置中，AFLNet 将忽略响应，并且不会根据响应代码构建状态机。 因此，AFLNet 无法使用状态机来指导探索。

## 3. When I need -c option and what I should write in the cleanup script?
3. 当我需要 -c 选项时，我应该在清理脚本中编写什么？

You may need to provide this option to keep network fuzzing more deterministic. For example, when you fuzz a FTP server you need to clear all the files/folders created in the previous fuzzing iteration in the shared folder because if you do not do so, the server will not be able to create a file if it exists. It means that the FTP server will work differently when it receives the same sequence of requests from the client, which is AFLNet in this fuzzing setup. So basically the script should include commands to clean the environment affecting the behaviors of the server and give the server a clean environment to start.

您可能需要提供此选项以使网络模糊测试更具确定性。 例如，当您对 FTP 服务器进行模糊测试时，您需要清除共享文件夹中先前模糊测试迭代中创建的所有文件/文件夹，因为如果不这样做，服务器将无法创建文件（如果存在）。 这意味着当 FTP 服务器从客户端（此模糊测试设置中的 AFLNet）接收到相同序列的请求时，它的工作方式会有所不同。 因此基本上脚本应该包含清理影响服务器行为的环境的命令，并为服务器提供一个干净的启动环境。

## 4. What is false-negative reduction mode and when I should enable it using -F?

4. 什么是假阴性减少模式以及何时应使用 -F 启用它？

Unlike stateless programs (e.g., image processing libraries like LibPNG), several stateful servers (e.g., the RTSP server in the above tutorial) do not terminate themselves after consuming all requests from the client, which is AFLNet in this fuzzing setup. So AFLNet needs to gracefully terminate the server by sending the SIGTERM signal (when -K is specified). Otherwise, AFLNet will detect normal server executions as hangs. However, the issue is that if AFLNet sends SIGTERM signal too early, say right after all request messages have been sent to the server, the server may be forced to terminate when it is still doing some tasks which may lead to server crashes (i.e., false negatives -- the server crashes are missed). The false-negative reduction mode is designed to handle such situations. However, it could slow down the fuzzing process leading to slower execution speed.

与无状态程序（例如 LibPNG 等图像处理库）不同，多个有状态服务器（例如上述教程中的 RTSP 服务器）在消耗完来自客户端的所有请求后不会自行终止，在这个模糊测试设置中，客户端是 AFLNet。 因此，AFLNet 需要通过发送 SIGTERM 信号（当指定 -K 时）来优雅地终止服务器。 否则，AFLNet 会将正常的服务器执行检测为挂起。 然而，问题是，如果 AFLNet 过早发送 SIGTERM 信号，例如在所有请求消息发送到服务器之后，服务器可能会在仍在执行某些任务时被迫终止，这可能会导致服务器崩溃（即， 漏报——服务器崩溃被遗漏）。 假阴性减少模式旨在处理这种情况。 但是，它可能会减慢模糊测试过程，从而导致执行速度变慢。