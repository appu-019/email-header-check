"use strict";

// Made-up examples for trying the page. They use the reserved example.com /
// example.net / example.org domains and documentation IP ranges (RFC 5737),
// so nothing here points at a real sender.

const EXAMPLES = {
  legit: `Delivered-To: you@example.org
Received: from mx.example.org (mx.example.org [198.51.100.7])
        by inbox.example.org with LMTP id 7Hq2;
        Tue, 17 Nov 2026 14:02:13 +0000
Authentication-Results: mx.example.org;
       dkim=pass header.i=@example.com header.s=s1 header.b=Kd9x2Q;
       spf=pass (mx.example.org: domain of bounces+8121@mail.example.com designates 192.0.2.10 as permitted sender) smtp.mailfrom=bounces+8121@mail.example.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=example.com
Return-Path: <bounces+8121@mail.example.com>
Received: from mail.example.com (mail.example.com [192.0.2.10])
        by mx.example.org with ESMTPS id x91kq2
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 17 Nov 2026 14:02:12 +0000
Received: from app-04.internal (app-04.internal [10.0.0.5])
        by mail.example.com (Postfix) with ESMTP id 4F2A1;
        Tue, 17 Nov 2026 14:02:10 +0000
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=s1;
        h=from:to:subject:date:message-id; bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=;
        b=Kd9x2Q...
From: Example Store <news@example.com>
To: you@example.org
Subject: Your order has shipped
Date: Tue, 17 Nov 2026 14:02:09 +0000
Message-ID: <shipping.8121@example.com>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8`,

  phishing: `Delivered-To: you@example.org
Received: from mx.example.org (mx.example.org [198.51.100.7])
        by inbox.example.org with LMTP id 2Kd8;
        Tue, 17 Nov 2026 09:41:30 +0000
Authentication-Results: mx.example.org;
       spf=softfail (mx.example.org: domain of transitioning service@paypal-verify.example.net does not designate 203.0.113.50 as permitted sender) smtp.mailfrom=service@paypal-verify.example.net;
       dkim=none;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=paypal-verify.example.net
Return-Path: <service@paypal-verify.example.net>
Received: from vps-77.example.net (unknown [203.0.113.50])
        by mx.example.org with ESMTP id 9QXw1;
        Tue, 17 Nov 2026 09:41:28 +0000
Received: from localhost (localhost [127.0.0.1])
        by vps-77.example.net with SMTP;
        Tue, 17 Nov 2026 06:10:02 +0000
Authentication-Results: paypal.com; spf=pass smtp.mailfrom=paypal.com;
       dkim=pass header.d=paypal.com; dmarc=pass header.from=paypal.com
From: "service@paypal.com" <service@paypal-verify.example.net>
Reply-To: case-review@example.com
To: you@example.org
Subject: =?UTF-8?Q?Your_account_has_been_limited_=E2=9A=A0?=
Date: Sun, 15 Nov 2026 03:12:00 +0000
Message-ID: <20261115031200.77@vps-77.example.net>
X-Mailer: PHPMailer 6.8.0
MIME-Version: 1.0
Content-Type: text/html; charset=utf-8`,
};
