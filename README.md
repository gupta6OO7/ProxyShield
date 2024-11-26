# ProxyShield

## Overview
ProxyShield is a multithreaded HTTP/HTTPS proxy server written in **C**. It efficiently handles requests, caches responses, filters content, and supports custom cache replacement policies. The server can manage multiple concurrent client connections and block content based on keywords or URLs.

## Features
- **Caching Mechanism:** Caches responses to improve performance. Supports:
  - **LRU (Least Recently Used)**
  - **FIFO (First-In, First-Out)**
  - **LFU (Least Frequently Used)**
- **Content Filtering:** Blocks requests and responses containing forbidden keywords or accessing blacklisted URLs.
- **Concurrency:** Supports up to 400 concurrent clients using multithreading.
- **Error Handling:** Returns appropriate HTTP error responses (e.g., 403 Forbidden, 404 Not Found).

## Prerequisites
- **GCC/G++ Compiler**
- **Linux environment** (recommended)

## Installation
**Clone the repository:**
   ```bash
   git clone https://github.com/gupta6OO7/ProxyShield
   cd ProxyShield
   ```

**Build the project:**
   ```bash
   make
   ```

## Usage
**Start the proxy server:**
   ```bash
   ./proxy 8080
   ```

## Configuration
**Blocked Keywords and URLs:**
Edit the *blocked_keywords* and *blocked_urls* arrays in *proxy_server_with_cache.c* to customize content filtering:

   ```bash
   const char *blocked_keywords[MAX_BLOCKED_KEYWORDS] = {"blockword1", "blockword2"};
   const char *blocked_urls[MAX_BLOCKED_KEYWORDS] = {"www.blockedsite.com", "www.example.com"};
   ```

**Cache Replacement Policy:**
Set the desired cache policy in the *main* function:

   ```bash
   set_cache_policy(LRU);  // Options: LRU, LFU, FIFO
   ```

