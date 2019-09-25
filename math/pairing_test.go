// Copyright (c) 2019 lambdastorage.com
// --------
// This file is part of The proofDP library.
//
// The proofDP is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The proofDP is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the proofDP. If not, see <http://www.gnu.org/licenses/>.

package math

import (
	"crypto/rand"
	"math/big"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	pairingTestRound = 128
)

var samplePairingIns = []string{
	"k8AWC4L+aLvN7cncobaE4BOTdavR5rgR8n3CPVWHq0+3GU5YsMLVw/dy2AlNDoSgPAp9KYVQSfBlV4ZwhQe9NCDxKy1Dv0GHbfg+n3SIVhMqDoIV4FsxOrHv5Q1suexp/2Gt4eg/+l1pmiEO5raghuQYeBeEEDLDVCT8RP49jO0=,H+tZGAWztL2ibGhUFEkwu9JcsUrf4teo5H+CvRRsnjVIHMg//OWItl3p+1Q+IvXJVP8lYFVwd6/T1RsK62Ey5IQTVNRd/TCiugnVz7U5jeOXgkPbM1/o0Gv6vVrOdaTSEEK2b1uuKX60BZvGSErMv/rx+Zb9msQvoHbJ6rwZEQ8=",
	"XNqiNbWpJXUXk0MNFdSNtd2VZE22LIrjCGn8f+WsGbGLny4bsFGkjkx9IM55FEOVPnkgzW33LhEZLUrBV0xgn4l0GAG4g/+46cfHleWCJUgzrWCuCnjyXEvbk6Dqitw0K1nVxYDFY6Z3Imroyon4qYTReo0kuxJYkQ5wXwBkXPA=,QwvdlKr/GFyV1dflCpgJYrzuGM+M+gXnCSVIyQFj1TDeRfUQ9VMmVizEnlcQqV9yoQQr0MB15Mhf0075tX+F5iv7ilHsiaBmbVFscFE5rCymeN/CiZTqwGFhcpVbChNpX/SyMRyeq2IvjcIwkHG+jG/FRa7kqjILI/2XfciNJL8=",
	"Qytwv4BsMO2pQlNSbRT6JrLV2sPKV4nkie2gKAhUWpt4yra2+29Qbia/Vh0PvNoKdq3Bx6+4diabOmgiuQcNI5fF8QO7tIw84of9frOW0/cDplGnOy+g9iGsfvHWd7UtEJGaYw/K55PAh/hzP0SdM09ktLldcZlaLI1YRMtOdkU=,CubYtiOiPVrbawfceha7rkrUX7vzmJFLAeRWfhwfEThEyDbs6GIajhRnoqRp1esD8T8cOIW5x4d9PZforo+xch71XK3jFEzR5Z07ucb3oeOs8YGzB9Prv5bLvBtA/S8+n0qTgOHHsR+g4Q5XMDmKiYYfrvtskw7WATHQ0gi7CnI=",
	"k56+0tvfLB3O2mYiByoMAQ43vWQEy3sXMPZNx6IV4vsusCAOXzLR0F/uz8fSggf/QXiTp/MXS/JqXACCQMk+YVGk4ANtwZSxg9gGyfiaWO3yNAzbysd/69+PCAie3Krz7k8kUWMbuyR6u76zVC7gzIG4yo82jcTGfAYfJFAPVhM=,Rj4+V/GYe75e82MDJ70ZVSOpsA+S2bYVHQ7bOxMJxO/B9KdKzOE9/lkY7m4RA9gnKdLDcHE0srGTUbR+f5TRBy1FTU6MxxkqR7Imj0Z4fxjE8XV3y/B/OsVRZS9RlYpcyx01UE1nSIYnTFH5lYuYnI1rfmA2qepuuz+4WzjWmPw=",
	"OCAkxLXxS0FAZCLq/322rnUMi11wWwgFmUabS9xmJDk21Vl2jYLpDIvQRRgnRLLT5B+q4MCNpABEgjljqOyfypbBjZ9kmEOfy+DTTIKCn8E00njcAi/VJU2iNxndLvKBsnoM7geCl6lbts54+grbSFlgavc5FV2KcV1d+8HSZVA=,i2csXUm1BSl82rhrsGYv7fILHCIT8J8TYgo2IEn6q1vhCNb1MvxoTVCPqNRdlX6Eq+sz8q86Kq3h8r2QoOHOFw1DjotoommcqlpNT+opUp837kwn7niqFZXcMgpI3vo5PoR7litd8ae25KiUZnsJbZJoHFMmO5aV958P5uTXaXw=",
	"OlxMqzgl52NEKMGJrNF/M/ozoud8kt62qAKJnPe3hEErfQ7tkMejsSw8kFWOgMsNEFLRIhs+yJbzETCHcvzqvFSrp0otRRJpBpArGZhvX24ekiVtO/o3YtCqxVx/xOeVCJZMQL0ZpC3UCN0CgdoeLfMx2riX13k0TKkHrSUFzrY=,UDjuxH/PE9na9AVLwGsPunQ2WHzyC5NHMfaCG41IDeKr/rN+DsXzyhmZ4lSAUB0abe6pZSAGDJgqXHaSPujIZn5aG+7tT0OQNij8p3fYShxbZhbIPSPODnwMml8wbB1vEwKVvqeelQq9keZZq/a7GtDl/x6MO/gT4tG44dfaOY0=",
	"ByIlVFUUoRm981raiTaE9Qx8Mt2J0b+UKv9Pxgj23sUNLulscQsFTUj30yW0ZWU3ZDW27Qz1e/strdscp3RnhzY9oA78poWDXgn9fVGxU3VRAqad+sZRvHE3ou4xnyjcg9Vl+amU8PeOlVqiD3X9LYXAw9pa3zJy9+TfweljD8w=,F7WQwi88Lj9PZa/sgZ5UfXpTxuFhaCUl6hUWfTp9FBgsp4YjeHrb9ALgOTcXlPWI4RTKwyBVt4usabogR7fh3EDsDBHKVE+iRhUuoGsaDf/B9Wul2LdeJAgpfFTbSXZ4A1Vqy5zy8HYIi7dhHGu3XAjid0Z8HlkApvVWKUOZRz8=",
	"Il2GnRs7DXDVUz2pzSxuF4jHVlp6NYgr3obPuK7xr2c+J+KJKq5uuYRBNg73hqiYQrx3I0xxi8lB+g4jqqvl3W9Clxp2WPPqNMvvhdMwZn493HkLWWUM9ZG8UlRl5sMY2NbLyzcnjCCQMzQXna/MD9dylCt+S1wjPSr2CjE6KOA=,R683UYl5sOa2KtVqZgLo5fIgLgg/3m9rryWJm8XlA8AWzzbuyw8wtwAU4JT+KdYLtMAA1YfREhTL1EQUbGG0k28Tynf5kf4VbHq2YFEsHGrYpHiS16y5MlNyXUMmAzXIrfTJHSNY4BazPdKryIXszjsQsHrnIqIAIG8tcvQVBJ4=",
	"D44As8FZfQwsNCha9hPZ1F/Lvj9fNTnLchkNli90rgyZS4TOWKyqPpBeHcQyXW2nt/5X2XiIrpe3xLnQfkzLPG9E8Zil7611kDUbgqxYFrDoQI1FQkGeRn6cZdy4h6CRYUkd85+4flnBNyzVApKWy0vDr0MV4aTpOSBMfdJml6U=,Wt5Gneytc2Qy8Yc6EFIjBLqDCQVcH2xvLZo3jkMlWeG2Bx2iL8s8WDihR7RExRVJWRRtd2DxMK45JaNtGm+DUGv7+Ylty3gMK8Es4ixY5Jhk3CputBxAUoT7asDdLPK2Za83P6An10Y/m3ioNV3s+u2ID7cKwtVdGXEvmhrm7qg=",
	"kV9cBmjQezYiHRimhMrGVQIkD5dE9BxTWXjW5p64FWitjgo48AgTXbDCz9sS0yz6nTGU15btkLrvcG+StWiG4aWO5+40Fqxxf2xQEgQTSikVmVj1nzEKmHOIk8FbXuDruCXNnOvKRJG4MSy1d4QVVeqMpTuhMT9wJJC4OxGDnhU=,i28Wb7ZR3kG/MDrRfrSc4LFryRWYQ1+mtKkFW/QG92TYqK+s4b8x1mf9I5gGBGJ3pOB7zjmppZsfW4G/SiWloUDgLW4X7JLYLMR3od4G3zgeZGgD69XbYLXQLN1qXC+6NxPxUfIdxkLusZea8GuK7OcRlQAE817vlYKNP6cAgOc=",
	"j7G+iMuhWf6Dc3B3Gqz8SW1UTW04XtvJlcjfmk3pJXQtKpcWqD7E5dYiheG2/nke2xKGxZ0c5SDem7kb0EwSIDXXYWGxH20lhVCOrJFdTMOkqr0wlGwCR3Qo5NrwGJW1JCT3rJYUnCRU7tNrhqlrzlDuq58T4lmbbXZF+eK7hMo=,XC4go6eskoFQBqFvlprWm8yj9nUVMpLFoahUbDO3gjYakdtquJ+P8nEEgnG5jA0Pgl8vST77w+aDpczgN8xhykJjVLWijQUvnQqhrrBDvjuJvwrEIDXGJcJoRYkU1xwGou+LpaSE8c23blj+xZuQMvR+8z04FnC+VaI9aukwU78=",
	"bO9nCZvGLNKFPqawos9cG5irVOUJKnpgRaSeUiVFEraOKxLAkbr+CpeIehpzMetxFZKfSoWrc8+NqWJaWZBg3yw0tybvuBJRi0sdDFyXbC8qTh7vUklFKbL+F6DzpVMIN21OhZkJeoRfZCosGTykGUhDEcnlc9xNGhHEAXQIZEw=,pxTOC9xej8QGqhK4eHLUeExutuQxF+jnemnAcXZfrGWUDvJ2OY90AJh+ghGEsGyOPRBUAlWqF7mVzxXFQ1MUpkY56DNKmrTlPu7vGXwBEb/anHuz+shLfQGhoCu+6pTluK/J0A43aZU8sZoNuZ/9lWgAitckvn/d6tpQ9JKdaPs=",
	"RH9NEXORty+13EjOn02jA2LHn3spVXJAc/2ZPf9Eie02L6kXRWihE6wUaS/LWChkVnEpP778lchqkHgcDA/ts3Xp0IBZkQmQcxlLNgvzNMIfw4WI6NaYX3Y4JpRjV/sGhxXo3doHV5+xFRVSrU9b8OisnSWrostIve/LBvdNfqE=,e56FUt1UW5oT+xfWjO2UnY4smjWVXpoGdnT7hCoTKQJN068RkllkK4hesG5kP+vftTT1+QbpVAxF3hN1SaqnlZFiRnMEadHyh57RxuI+UlVb8lqyvbCH29q5ikmfHliK1M5Fzi8//2RJNiAUPHPC+eaXKN+70wmVZ7bBUaKt5X4=",
	"BQ6eJ3nc/a8CnxaRtZHhZyrAFshirFWG/h9lx1m1vBchDfwS6xRIpRoArGMwdI0aJhDyOG5Je/4bIBi48EFesleRfR/q26IU3OXCSakQeS/ssIMb5W6Rbjl12Hwu3O9HVh3UgczMLQTsQFi8yYYXlv7KdBgEhnotcaZ2qLqBc1w=,OU/JcidgZUs9gD86g5nIdR09Q5IseqaYaM7uv5oVY6imlXiUcvJKzyFKHr2gxoDUW5MJNqweHH8YPGDvEkkiSiKy9cOdDqXLLok17D6yUIv1LoLQqgJsiRMCspq8Km1Z0V4iX7OQNITBNsP9oR4mmAtoO1jkgBBEBZ/R8ndXFLM=",
	"eHdi0jq9kmFaO3y9/lzSp8dtMBKsypdN4eiT4Czr1TmOJ8M8Ux+elBH29YhlUMq+qdGUSfCWzIiG1FkAKsdRYDwBvB8XJzbo6gPmshoI60rIrDYmOeNR0qgfk7TpwxefnaQR993T+Q30UXqTEB/DmBVJDCEOxl/LNdXD+8lxmsg=,k4EnnLkVUp9Sjtozf34FMUaZgEdsC2/X49dp/HYPaOQTBBzBtsqi9uXQIW//SaBD5hj1adYUHbJ3uYaJyqjB1y4Yh3IC0DJpJh4b0raio0AUIkqHvgN3+kPVtjwiuE6bft35pIhNIDyoZwhs2ZU10Y9zX1C80P/uOih0MojfTmM=",
	"T6rLl9trIYAbgYqaCBFtPopOW1y713X6GYMO6ivT3pxHE1RhofPbL5LBA5NJDNctRF44Jsc9OeixqDkosGA+Hmf5nRqev1qDITgBQxBZmmMH9AhmKZx5ezYtwJV2WbL/Tg7Jxk2keR06TE+2CDB2w62+9ULbLr+fgdZA49VptJ0=,M3BLx/U1V+DyiECquA4tim/jBajSmsdjazVapv7WBwa/Rs/o0fpvftWrttQPng8FODz52YbVhspz4i85V506c0LWPSgEMc3C3Ohx3H5QOhubG4zUTa+eeLc40tdJJFgRRRbx1Yvjtge4jrWALppSlPaoz5B+vLzmuUoL4OJIPhA=",
}

var samplePairingOuts = []string{
	"IDsl8dtMmVBI9cI30FyKKnGoM4BmFVi4c1FXxt+sS85z43fYknoJ/aw9S0NixN+CUPf+4wqXZpQbHlgCOlPxcCBWENpbPe3SFx0D3xbqEpOT51c1AxxcsL66Ba0iTpJUnkG07nukrNxKnFP9eMpzSX/vuizQSLr2Hb0q4e6nOog=",
	"epD64SvxZlkxwlqIdCTYlJVlZLljDmOjDmtULRlWaMSLwgGywO8VvMOvDQZTbXAO/gieptOHsqt8p4HCdk9LepoFhO5gsgZ6QR8aX3yI+xvDaC1B2qwdIWE4EafKX8byoUCTEXuph58m9ouQedtP5kEtI2NfGnvxUSeVNr2ezd4=",
	"gMdciAoNv9LZP1/AgTsgR1iDHZLrTmEhQXs6Ufi8sImQPNmrizes1QZru+zwax2YCTbzrx19Xv5gyBLoVpRRgSayeHPVuhXwlU0xW6S4j5TsT5WZBSb/ttv1HDuw3WJKgGWZ1Wzmt6koI0SOs09Qqs95hkkwp9bqSCuFSbDH/8k=",
	"o50T9nZTVCGq+OZ+hb5jieI2YP6ZP7XcMwGrydKktwixhZ1xYsITt7DH8XJbqyQWtZkoBOfJKILXYeqEI3NdT3ewLRjB2BsGV0x8JAVUMTDo2eLtNzXll5ozFXaFiiiwEA6Too1W3Cqj1++Yr63ew35GwATb3QYfVyTaOHGccQQ=",
	"PWrWEVmY3bg8I013aMabTP8UCjwp3BnHPIqNep5FoAoY2w9pPj+SAReuk7c3sQRnsmGjjjCONQSq/b78vl84iizh2fNz96pP5ORcklLdBOfp7/CwWdr0T8vwvORppe2W5VESqeEscYjJ1zewwBcegX0muUKMLS9z9AG4DlrXfbk=",
	"IKoS0KbB1qGKenpqG60v/2K5Fs1gSU1UXpPbDJAX7qUA59bqMTrDiXCGdKc9yqQSffLhV0CReUniAipKRiw8uQ+gMGscZjabgbae2R3m4qPGNikzgdEE8DvhoolUjNGlMgakYRgsspNh4b4AhylcwLBMbVn5IK837txVOLOzJ3Y=",
	"UgILeDd/cJuaISPwSD7XSkrGwZR9KHLpPiH80+qpKJSkkjDQ4JKuU7wGaww04G3qJESYSF6pd5gdI7IxghDnYnlq325CqjM0l3m3iQfsJoTkWFN4f+iZ+FQZurSl8zngI6ZSvAgh+VzWq/Wz4KM2Ka9x19csDdaX/W/lr3DsRdU=",
	"fFhLj15WeS9lLUFS+H3V75DkM+kBk0EjWoX9MgXyNYA30PtpcN1raF93uat1crqts/PCGfNH21aWRzmr4cCrPm91qZi1LdhlOaZ+HYVi01OP+t8MXmj5owp8ecfe6pjJw2e4rPnOThWBF/xqYPmUVPHyRN7C09vYn+5YEZ2vVss=",
	"CkYQLaRt/Oy0v4+NuzArFAZlTafeLC/om4hCd1DETxL7B3NeZYCUgMjliiz62kCaLirD8z8xeZinVs1iZXibcpbvi4IcCchT8C468DsAIetsV84gdjxHsXvEPwr5LyGjlcBdRWCncPuv8DFo6HFaT/872+JpIrYcczZ86W+ucEQ=",
	"SEJIQKnDyOm1h9BWlwFsh7n/mCCr8pNyVEKk891saN+mW7sf57ogV0LxuRDPZ+OinyBTXnyYn8z+9lTqjpvR/gxC+6QSKAFuBMCLNdSbyp+Tw0rfBDA1M96IDWVlk5CThsLgJp9kVX4k3DkyAB1RZ0hyYttWK+8vLJwriqmxG3A=",
	"k7bDgaAGLkaZ/TXlD+4SZ6hROypB3OETSpPYW9F2SGHVbRlunYR5rIjwUBIlsPmoILKWUJaOcPUnskK8vvjr3w8AAZASmUTt7FgOhWyKCBJxZjnNcd1RU9sDMUReupX241JEVBrkdgVQR7tAGI/DMl23S/SmLiQKBBGHq2DQVF0=",
	"IqJ2eHCpdIvJoMGra7q7c16YCiqEBdxCxMydlecW7FRjKVwPmu7aa920atI1cIMY2PBXmEFX/QBcu9NDlLhOZUkY5D2c25SWo5uSs6oi4EHhEgTTWhXt5/j8Y/OH9Ja8n9UvDM5JmhxnKzc10X3d32U8VuUm7XemMSx1gJAawwY=",
	"A9IXYA1vLUi8Y90WWyJYc3uKar7LOJKHy3Et3bGl3rot78Kpgqjs5AkkSZaaX89KSizyY7cLFYlGko9nqPerfj+eDR/SIA4zU78fp45i6eaVLTi7+ZEeVP/TISRJ1FwrNYskxWSgNxKBXG5oXziHIcH72aKEJvGfQxQFqhYcIZc=",
	"ieLmikND6bmj/4oyLEDaF6XRNAHsMENpKpbH5u+k1DBoKuda3POJr931gyhhNK2jMtTAc/IFw6rFFaZaSoJ8lJTRRrzbnkSNX+87SvLXapjaCI2VRjcsoaXi4o/bJiAFfFP+p8uLpvGjnlA4HkNO6uVTh02Q91YFGO4HMFqvxHg=",
	"aer1zV9ULPs+fh7rN4njeeUz8Kd/kGf+oCEING6Ax1Tb41cXA4h6Vnn/wspHYb56X5O7vNhjMjppNdTxFQF+7whF6fun9TmqatZpLEljGUd57tfZ5dGuwLSKoEQ8RtIRv3cu6njLUoe5yyZNbSuEbGxx1l43L78OpM7XHmE0arc=",
	"kb0qflW95RnsHhKgdlRoUY0hGA72qjzzXzhrwc3RCDxLGCSRET97yNUHiffRuTnu1t4Kzzf0z04AwhOpZ6Rp8Z8ooazcjqq06kZXl6r95x22O9VX8SWlGhL8SLCxz5KauzweDn0tR7kvDX4LgIArXPUgK4ANFUaY/KxNHQfKIck=",
}

func TestBiLinearMapByCase(t *testing.T) {
	for i, sampleIn := range samplePairingIns {
		inputs := strings.Split(sampleIn, ",")
		result := samplePairingOuts[i]

		aValue, err := fromBase64Str(inputs[0])
		assert.NoError(t, err)
		bValue, err := fromBase64Str(inputs[1])
		assert.NoError(t, err)

		a := newCurP().setBytes(aValue)
		assert.True(t, validateCurP(a))
		b := newCurP().setBytes(bValue)
		assert.True(t, validateCurP(b))
		out := biLinearMap(a, b)

		assert.True(t, strings.Compare(result, toBase64Str(out.bytes())) == 0)
	}
}

func TestBiLinearMapByProperty(t *testing.T) {
	for i := 0; i < pairingTestRound; i++ {
		u, err := randCurP()
		assert.NoError(t, err)
		assert.True(t, validateCurP(u))

		a, err := rand.Int(rand.Reader, gFQ.ord)
		assert.NoError(t, err)
		uPowA := newCurP().powN(u, a)
		assert.True(t, validateCurP(uPowA))

		v, err := randCurP()
		assert.NoError(t, err)
		assert.True(t, validateCurP(v))

		b, err := rand.Int(rand.Reader, gFQ.ord)
		assert.NoError(t, err)
		vPowB := newCurP().powN(v, b)
		assert.True(t, validateCurP(vPowB))

		lhs := biLinearMap(uPowA, vPowB)
		rhsExp := new(big.Int).Mul(a, b)
		rhsBase := biLinearMap(u, v)
		rhs := newQuadE().powN(rhsBase, rhsExp)
		assert.True(t, lhs.equal(rhs))
	}
}
