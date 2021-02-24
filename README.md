# QBLKe
An OCSSD host-based FTL.

## Run QBLKe

**1. Prerequisites**

QBLKe is an Open Channel SSD(OCSSD) driver. So, your server should have an Open Channel SSD which supports [Open Channel SSD specification 1.2](https://openchannelssd.readthedocs.io/en/latest/specification/).

If you do not have an Open Channel SSD hardware, you can use [FEMU](https://github.com/ucare-uchicago/femu) to emulate an Open Channel SSD for your QEMU virtual machine. If you choose to use FEMU, we recommend FEMU commitID [783d4fb4ce46e0e10ef83d48046566cbba1e6b6d](https://github.com/ucare-uchicago/FEMU/commit/783d4fb4ce46e0e10ef83d48046566cbba1e6b6d).

We provide an example FEMU startup script `QBLKe64.sh` in the `tools` directory. Please modify to fit your configurations before running.

**2. Linux Kernel.**

Currently, QBLKe is based on Linux 4.16.0.

If your kernel is cloned from `https://github.com/torvalds/linux`, the commitID of 4.16.0 should be 0adb32858b0bddf4ada5f36.

**3. Download QBLKe.**

```
git clone https://github.com/WNLO-DSAL/QBLKe
```

**4. Tweaks for FEMU**

If you are using FEMU, do the additional tweaks described in [https://github.com/ucare-uchicago/FEMU/wiki/FEMU-Best-Practice](https://github.com/ucare-uchicago/FEMU/wiki/FEMU-Best-Practice).

**5. Apply QBLKe's kernel patch.**

QBLKe relys on the lightNVM infrastructure, but we changed some interface between lightNVM and device driver. So, you may need to overwrite some files. (e.g. core.c)

If your linux kernel source resides in `/usr/src/kernels/linux`, you can use our script to copy files.

```
cd QBLKe
./cpFiles.sh
```

**6. Build kernel.**

Here's [a nice article from kernelnewbies](https://kernelnewbies.org/KernelBuild) for buiding instructions.

Don't forget to enable lightNVM(`NVM=y`) and disable pblk(`NVM_PBLK=n`). After compilation, restart and login to the new kernel.

**7. Build QBLKe.**

```
cd QBLKe/qblke
make -j16
```

**8. Install nvme cli.**

```
git clone https://github.com/linux-nvme/nvme-cli
cd nvme-cli
make
make install
```

**9. Run QBLKe.**

The shell script "install.sh" in the `qblke` folder shows an example of using QBLKe.

You will get a block device in `/dev/qblkdev`. Then you can play with it using mkfs or fio.


## Pre-built FEMU image

Another way to try QBLKe is to use our pre-built FEMU image.

**How to download**

* Via Baidu Netdisk: [Link](https://pan.baidu.com/s/1GTU4uQR_zP-C1XgtCgSN3g) code:2283

* Go to the release page of this repo [link](https://github.com/WNLO-DSAL/QBLKe/releases/tag/femu_image). Download all the files starts with "x", and place them in a directory named "QBLKe_image_dir". A sha1 file `QBLKe_image.tar.gz.sha1` is also available to check the integrity (See below).

* More ways will be available in the future.

**How to use the pre-built FEMU image**

We splitted our compacted image into several parts. So, the first thing to do is to concatenate the splitted files and then extract the files.

```
cd QBLKe_image_dir
cat ./x* > QBLKe_image.tar.gz
```

You can check the integrity of QBLKe_image.tar.gz by:

```
sha1sum QBLKe_image.tar.gz
```

Extract files:

```
tar -zxvf QBLKe_image.tar.gz
```

You will get three files: `ImageUsage.md`, `QBLKe64.sh`, and `QBLKeImage.qcow2`.

Then, follow the instructions in `ImageUsage.md` to run the VM.

**FYI**

1. DON"T use the latest version of FEMU (due to the OCSSD spec issue). Use the one stated above.
2. By default, the `QBLKe64.sh` creates a VM with 32 cpus, 8GiB memory, and 64GiB OCSSD (which is emulated using host memory). Make sure your host machine has enough resource before using it. You can change the settings by modifying the script.

