# QBLKe
An OCSSD host-based FTL.

## Run QBLKe

1. QBLKe is an Open Channel SSD(OCSSD) driver. So, your server should have an Open Channel SSD which supports [Open Channel SSD specification 1.2](https://openchannelssd.readthedocs.io/en/latest/specification/).

If you do not have an Open Channel SSD hardware, you can use [FEMU](https://github.com/ucare-uchicago/femu) to emulate an Open Channel SSD for your QEMU virtual machine. If you choose to use FEMU, we recommend FEMU commitID [783d4fb4ce46e0e10ef83d48046566cbba1e6b6d](https://github.com/ucare-uchicago/FEMU/commit/783d4fb4ce46e0e10ef83d48046566cbba1e6b6d).

2. Download Linux kernel source. Checkout to version 4.16.0.

3. If you are using FEMU, do the additional tweaks described in [https://github.com/ucare-uchicago/FEMU/wiki/FEMU-Best-Practice](https://github.com/ucare-uchicago/FEMU/wiki/FEMU-Best-Practice).

4. Download QBLKe.

```
git clone https://github.com/WNLO-DSAL/QBLKe
```

5. Apply QBLKe's kernel patch.

QBLKe relys on the lightNVM infrastructure, but we changed some interface between lightNVM and device driver. So, you may need to overwrite some files. (e.g. core.c)

If your linux kernel source resides in /usr/src/kernels/linux, you can use our script to copy files.

```
cd QBLKe
./cpFiles.sh
```

6. Build the kernel. Don't forget to enable lightNVM(NVM=y) and disable pblk(NVM_PBLK=n). Restart and login to the new kernel.

7. Build QBLKe.

```
cd QBLKe/qblke
make -j16
```

8. Run QBLKe. The shell script "install.sh" in the `qblke` folder shows an example of using QBLKe.



## Pre-built FEMU image

If you would like to try QBLKe using our pre-built FEMU image, you can download it from the release page.
Since github only accepts less than 2GiB files, we split our compacted file into small files.
To get our pre-built image, simply download all the released files into a folder, say `QBLKe_image_dir`.

```
cd QBLKe_image_dir
cat ./x* > QBLKe_image.tar.gz
tar -zxvf QBLKe_image.tar.gz
```

You will get three files: `ImageUsage.md`, `QBLKe64.sh`, and `QBLKeImage.qcow2`.

Follow the instructions in `ImageUsage.md` to run the VM.

