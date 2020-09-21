Attribute VB_Name = "Module1"
Private Sub VolgaCTF()
    Dim Var1 As String
    Dim Var2 As Long
    Dim Var3 As Long
    Dim Var4 As Long
    Var1 = Range(Chr(76) & Chr(&H31) & Chr(Int("53")))
    For Loop1 = 1 To Len(Var1)
        Var2 = 0
        For Loop2 = 1 To Len(Var1)
            Var3 = CInt(Cells(99 + Loop1, 99 + Loop2).Value)
            Var5 = Mid(Var1, Loop2, 1)
            Var2 = Var2 + Var3 * Asc(Var5)
        Next Loop2
        Var4 = CLng(Cells(99 + Loop1, 99 + Len(Var1) + 1).Value)
        If (Var4 <> Var2) Then
            MsgBox GenBox("yrr9VuqqcE" & Chr(&H54) & Chr(&H67) & Chr(Int("&H59")) & Chr(102) & "V" & Chr(Int("86")))
            Exit Sub
        End If
    Next Loop1
    MsgBox GenBox(Chr(Int("109")) & "q" & Chr(Int("49")) & Chr(Int("57")) & Chr(&H56) & Chr(&H65) & Chr(76) & Chr(Int("112")) & Chr(Int("86")) & "F" & Chr(Int("114")) & Chr(-343 + 395) & Chr(&H32) & Chr(72) & Chr(Int("&H31")) & Chr(100))
End Sub

Public Function LxGBqLt(ByVal VUGL As Long, ByVal zNaYtz4UaqnE As Byte) As Long
    LxGBqLt = VUGL
    If zNaYtz4UaqnE > 0 Then
    If VUGL > 0 Then
    LxGBqLt = Int(LxGBqLt / (2 ^ zNaYtz4UaqnE))
    Else
    If zNaYtz4UaqnE > 31 Then
    LxGBqLt = 0
    Else
    LxGBqLt = LxGBqLt And &H7FFFFFFF
    LxGBqLt = Int(LxGBqLt / (2 ^ zNaYtz4UaqnE))
    LxGBqLt = LxGBqLt Or 2 ^ (31 - zNaYtz4UaqnE)
    End If
    End If
    End If
End Function

Public Function BLHw9RCgXH4P(ByVal VUGL As Long, ByVal zNaYtz4UaqnE As Byte) As Long
    BLHw9RCgXH4P = VUGL
    If zNaYtz4UaqnE > 0 Then
    Dim Loop1 As Byte
    Dim m As Long
    For Loop1 = 1 To zNaYtz4UaqnE
    m = BLHw9RCgXH4P And &H40000000
    BLHw9RCgXH4P = (BLHw9RCgXH4P And &H3FFFFFFF) * 2
    If m <> 0 Then
    BLHw9RCgXH4P = BLHw9RCgXH4P Or &H80000000
    End If
    Next Loop1
    End If
End Function

Public Function d2GdYER7m(ByVal m2dGOJdUqmej As Long) As Long
    Const QXxRd0BK8l As Long = 5570645
    Const nfydVLY3E As Long = 52428
    Const d1 = 7
    Const d2 = 14
    Dim t As Long, u, out As Long
    t = (m2dGOJdUqmej Xor LxGBqLt(m2dGOJdUqmej, d2)) And nfydVLY3E
    u = m2dGOJdUqmej Xor t Xor BLHw9RCgXH4P(t, d2)
    t = (u Xor LxGBqLt(u, d1)) And QXxRd0BK8l
    out = (u Xor t Xor BLHw9RCgXH4P(t, d1))
    d2GdYER7m = out
End Function

Public Function AvOyEfnB2j(ByRef kmYz() As Byte) As String
    Dim Loop1, fr, NhfEdYPRadl0, raw As Long
    Dim a As String, b As String, c As String, d As String
    Dim rwHd As String
    Dim P2Y3dIxyB() As String
    Dim a2, b2 As String
    rwHd = ""
    For Loop1 = 0 To (UBound(kmYz) / 4 + 1)
    fr = Loop1 * 4
    If fr > UBound(kmYz) Then
    Exit For
    End If
    NhfEdYPRadl0 = 0
    NhfEdYPRadl0 = NhfEdYPRadl0 Or BLHw9RCgXH4P(kmYz(fr + 3), 24)
    NhfEdYPRadl0 = NhfEdYPRadl0 Or BLHw9RCgXH4P(kmYz(fr + 2), 16)
    NhfEdYPRadl0 = NhfEdYPRadl0 Or BLHw9RCgXH4P(kmYz(fr + 1), 8)
    NhfEdYPRadl0 = NhfEdYPRadl0 Or kmYz(fr + 0)
    raw = d2GdYER7m(NhfEdYPRadl0)
    a = Chr(LxGBqLt((raw And &HFF000000), 24))
    b = Chr(LxGBqLt((raw And 16711680), 16))
    c = Chr(LxGBqLt((raw And 65280), 8))
    d = Chr(LxGBqLt((raw And 255), 0))
    rwHd = rwHd + d + c + b + a
    Next Loop1
    AvOyEfnB2j = rwHd
End Function

Public Function GenBox(kmYz As String) As String
    Dim Jd1hAR9d() As Byte, dLX7nArx0N() As Byte, arrayByte3(255) As Byte
    Dim w3LFFcD1yIJA(63) As Long, arrayLong5(63) As Long
    Dim csWl(63) As Long, RFWT526u88I As Long
    Dim a8HxGZsyEvL As Integer, iter As Long, Z000a As Long, c0Xzfacy As Long
    Dim rwHd As String
    kmYz = Replace(kmYz, vbCr, vbNullString)
    kmYz = Replace(kmYz, vbLf, vbNullString)
    c0Xzfacy = Len(kmYz) Mod 4
    If InStrRev(kmYz, "==") Then
    a8HxGZsyEvL = 2
    ElseIf InStrRev(kmYz, "" + "=") Then
    a8HxGZsyEvL = 1
    End If
    For c0Xzfacy = 0 To 255
    Select Case c0Xzfacy
    Case 65 To 90
    arrayByte3(c0Xzfacy) = c0Xzfacy - 65
    Case 97 To 122
    arrayByte3(c0Xzfacy) = c0Xzfacy - 71
    Case 48 To 57
    arrayByte3(c0Xzfacy) = c0Xzfacy + 4
    Case 43
    arrayByte3(c0Xzfacy) = 62
    Case 47
    arrayByte3(c0Xzfacy) = 63
    End Select
    Next c0Xzfacy
    For c0Xzfacy = 0 To 63
    w3LFFcD1yIJA(c0Xzfacy) = c0Xzfacy * 64
    arrayLong5(c0Xzfacy) = c0Xzfacy * 4096
    csWl(c0Xzfacy) = c0Xzfacy * 262144
    Next c0Xzfacy
    dLX7nArx0N = StrConv(kmYz, vbFromUnicode)
    ReDim Jd1hAR9d((((UBound(dLX7nArx0N) + 1) \ 4) * 3) - 1)
    For iter = 0 To UBound(dLX7nArx0N) Step 4
    RFWT526u88I = csWl(arrayByte3(dLX7nArx0N(iter))) + arrayLong5(arrayByte3(dLX7nArx0N(iter + 1))) + w3LFFcD1yIJA(arrayByte3(dLX7nArx0N(iter + 2))) + arrayByte3(dLX7nArx0N(iter + 3))
    c0Xzfacy = RFWT526u88I And 16711680
    Jd1hAR9d(Z000a) = c0Xzfacy \ 65536
    c0Xzfacy = RFWT526u88I And 65280
    Jd1hAR9d(Z000a + 1) = c0Xzfacy \ 256
    Jd1hAR9d(Z000a + 2) = RFWT526u88I And 255
    Z000a = Z000a + 3
    Next iter
    rwHd = StrConv(Jd1hAR9d, vbUnicode)
    If a8HxGZsyEvL Then rwHd = Left$(rwHd, Len(rwHd) - a8HxGZsyEvL)
    GenBox = AvOyEfnB2j(StrConv(rwHd, vbFromUnicode))
    GenBox = H7OcueV(GenBox, "~")
End Function

Function H7OcueV(XbV06P As String, Oo09VD2mg As String) As String
    Dim y15BD As Long
    Dim o37xpQJ1uiv70() As String
    o37xpQJ1uiv70 = Split(XbV06P, Oo09VD2mg)
    y15BD = UBound(o37xpQJ1uiv70, 1)
    If y15BD <> 0 Then
    XbV06P = Left$(XbV06P, Len(XbV06P) - y15BD)
    End If
    H7OcueV = XbV06P
End Function
