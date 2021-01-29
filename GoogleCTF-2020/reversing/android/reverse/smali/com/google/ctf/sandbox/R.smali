.class public final Lcom/google/ctf/sandbox/R;
.super Ljava/lang/Object;
.source "R.java"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/google/ctf/sandbox/R$styleable;,
        Lcom/google/ctf/sandbox/R$style;,
        Lcom/google/ctf/sandbox/R$string;,
        Lcom/google/ctf/sandbox/R$mipmap;,
        Lcom/google/ctf/sandbox/R$layout;,
        Lcom/google/ctf/sandbox/R$id;,
        Lcom/google/ctf/sandbox/R$drawable;,
        Lcom/google/ctf/sandbox/R$color;,
        Lcom/google/ctf/sandbox/R$attr;
    }
.end annotation


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 10
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public static ő(JJ)[J
    .locals 11
    .param p0, "a"    # J # g_arr[g_int]
    .param p2, "b"    # J # 0x1,0000,0000L

    .line 22
    const-wide/16 v0, 0x0

    cmp-long v0, p0, v0

    const/4 v1, 0x2

    if-nez v0, :cond_0

    .line 24
    new-array v0, v1, [J

    fill-array-data v0, :array_0

    return-object v0

    .line 26
    :cond_0
    rem-long v2, p2, p0 # v2 = p2 % p0

    # 找最大公因數?
    invoke-static {v2, v3, p0, p1}, Lcom/google/ctf/sandbox/R;->ő(JJ)[J

    move-result-object v0

    .line 28
    .local v0, "r":[J
    new-array v1, v1, [J

    const/4 v2, 0x1

    # v3: r[1]
    aget-wide v3, v0, v2

    # v5: b // a
    div-long v5, p2, p0

    const/4 v7, 0x0

    # v8: r[0]
    aget-wide v8, v0, v7

    mul-long/2addr v5, v8

    sub-long/2addr v3, v5

    aput-wide v3, v1, v7

    aget-wide v3, v0, v7

    aput-wide v3, v1, v2

    return-object v1

    :array_0
    .array-data 8
        0x0
        0x1
    .end array-data
.end method
