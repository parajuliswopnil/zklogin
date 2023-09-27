import {SuiClient, getFullnodeUrl} from '@mysten/sui.js/client'
import { Ed25519Keypair } from '@mysten/sui.js/keypairs/ed25519';
import { getZkSignature, jwtToAddress } from '@mysten/zklogin';
import { TransactionBlock } from '@mysten/sui.js/transactions';

import { generateNonce, generateRandomness } from '@mysten/zklogin'


const suiClient = new SuiClient({url: getFullnodeUrl("devnet")})

const { epoch, epochDurationMs, epochStartTimestampMs } = await suiClient.getLatestSuiSystemState();

const maxEpoch = epoch + 2

var ephermalKeyPair = Ed25519Keypair.deriveKeypairFromSeed("b695d954a74c8428c42f6daab51c7ada25d8f225df94b255d11d862e71b20a7e")

console.log(ephermalKeyPair.getPublicKey().toSuiAddress())


const randomness = generateRandomness()
const nonce = generateNonce(ephermalKeyPair.getPublicKey(), maxEpoch, randomness)

const REDIRECT_URI = 'https://sui.io';

const params = new URLSearchParams({
   // When using the provided test client ID + redirect site, the redirect_uri needs to be provided in the state.
   state: new URLSearchParams({
      redirect_uri: REDIRECT_URI
   }).toString(),
   // Test Client ID for devnet / testnet:
   client_id: '25769832374-famecqrhe2gkebt5fvqms2263046lj96.apps.googleusercontent.com',
   redirect_uri: 'https://zklogin-dev-redirect.vercel.app/api/auth',
   response_type: 'id_token',
   scope: 'openid',
   // See below for details about generation of the nonce
   nonce: nonce,
});

const loginURL = `https://accounts.google.com/o/oauth2/v2/auth?${params}`;

console.log(loginURL)

var stringval  = "https://sui.io/#state=redirect_uri%3Dhttps%253A%252F%252Fsui.io&id_token=eyJhbGciOiJSUzI1NiIsImtpZCI6IjZmNzI1NDEwMWY1NmU0MWNmMzVjOTkyNmRlODRhMmQ1NTJiNGM2ZjEiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiIyNTc2OTgzMjM3NC1mYW1lY3FyaGUyZ2tlYnQ1ZnZxbXMyMjYzMDQ2bGo5Ni5hcHBzLmdvb2dsZXVzZXJjb250ZW50LmNvbSIsImF1ZCI6IjI1NzY5ODMyMzc0LWZhbWVjcXJoZTJna2VidDVmdnFtczIyNjMwNDZsajk2LmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwic3ViIjoiMTEwOTgzMjgyMDE4NjIxODQ2MTMwIiwibm9uY2UiOiJLa1I5U2JWX3hVT2hCZzNzU1Y0TkVKeW1MaHciLCJuYmYiOjE2OTU3OTc0MzcsImlhdCI6MTY5NTc5NzczNywiZXhwIjoxNjk1ODAxMzM3LCJqdGkiOiJlN2Y5OTE4ZTZhZTljZjUzNTAzMDBlZTRiOGFhZGI4MmQ2MTNiZDY5In0.aDalyAKIfxSeTv1dowCx_liJNfvqhQBmZaTp-hk3joacnTe9C9gluCXDnX7_o1DhkDdgsFqsy7_dzjPnsHpcbkSr8T8EBgpTZAQraVX-eb5Reas1YukdhIOOT6kFypALI81yj7jyj6ej7Tzx1poC_PhyAG4Lt30Cw0QSgSe01QGfmVEYexQ0rE1YGpFMheAPeJnc7LwsBq24ChBRjvMPBQ0xNYcW3Lkojl4J6PglXHet9DrEMp0vpA2zMgrggbYHNCtxq0YUyrTgNoJJ1STNYd5Fk_3AncCItmHA3RMAZZs6DCe-dUmLncI6UoJbtAeiOKIDIzbUaJlEEW2Ook1Pog&authuser=0&prompt=none"
var splitted = stringval.split("&")


var jwt = splitted[1].split("=")

console.log(jwt[1].toString())


const userSalt = 1000

const address = jwtToAddress(jwt[1], userSalt)



console.log(address.toString())

const client = new SuiClient({ url: getFullnodeUrl("devnet") });

const txb = new TransactionBlock();
txb.setSender(address)

const  bytes = await txb.build({client});
const {signature} = ephermalKeyPair.signTransactionBlock(bytes)

const zksign = getZkSignature({
    inputs, 
    maxEpoch, 
    userSignature: signature
})


client.executeTransactionBlock({
    transactionBlock: bytes, 
    signature: signature
})




function parseJwt (token) {
    var base64Url = token.split('.')[1];
    var base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    var jsonPayload = decodeURIComponent(window.atob(base64).split('').map(function(c) {
        return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
    }).join(''));

    return JSON.parse(jsonPayload);
}