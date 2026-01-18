---

title: "Forensic Writeup"
date: 2026-1-18
categories: [Forensic, Writeup]
tags: [ctf]
ctf_event: "TAMING25"

---



# TAMING Final Round Forensic Writeup - Alumni Category

by 171k

Kinda disappointed there are only 2 forensics challenges and  its.. too easy.

But here we go.

---

# 1. The Russian Doll

## Challenge Overview

We receive  `evidence.bin` to investigate. Thats it.

## Recon & Solution

During recon, i use strings read the content and the flag directly shows up.

![strings.png](R:\taming\Web\TAMING25-Alumni\Forensic\strings.png)

## Flag

```
ictff8{binwalk_is_your_best_friend}
```

I think the challenge creator wants us to binwalk to get the flag but.. there it is.

---

# 2.  Operation Broken Stripe

## Challenge Overview

We received `disk_0.bin` and `disk_1.bin`. We need to match these two fragments and craft the flag.



### Solution

When we look at the raw data from the disks using this 4-byte logic, the fragments align just nice.

| **Stripe** | **Disk** | **Raw Data** | **Reassembled Segment** |
| ---------- | -------- | ------------ | ----------------------- |
| 1          | Disk 0   | `ictR`       | `ictR`                  |
| 2          | Disk 1   | `ff8{`       | `ff8{`                  |
| 3          | Disk 0   | `41D3`       | `41D3`                  |
| 4          | Disk 1   | `_0_R`       | `_0_R`                  |
| 5          | Disk 0   | `c0vM`       | `c0vM`                  |
| 6          | Disk 1   | `3ry_`       | `3ry_`                  |
| 7          | Disk 0   | `4st`        | `4st`                   |
| 8          | Disk 1   | `3r}`        | `3r}`                   |

By combining these 4-byte blocks in order, we get the following string: `ictR` + `ff8{` + `41D3` + `_0_R` + `c0vM` + `3ry_` + `4st` + `3r}`



When read as a single sequence, the words **"RAID"**, **"0"**, **"Recovery"**, and **"Master"** emerge from the stripe boundaries:

- `ict` + `ff8{` -> Prefix: **`ictff8{`**

- `R` + `41D` + `3` -> **`R41D3`** (RAID)

- `_0_` -> **`_0_`** (0)

- `R` + `c0v` + `M` + `3ry` -> **`Rc0v3ry`** (Recovery)

- `_` + `M4st` + `3r}` -> **`_M4st3r}`** (Master)



Using all the words provided and the 4-byte RAID 0 reassembly pattern, the flag is:

`ictff8{R41D_0_R3c0v3ry_M4st3r}`

---

Thats it for the Forensic writeup for TAMING CTF Final Round - Alumni Category. Thanks for reading. 
