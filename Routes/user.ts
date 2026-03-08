import express, { Request, Response } from "express";
import  bcrypt from "bcryptjs";
import { User } from "../DB/user.ts";
import {createJWT} from "../auth.ts"

const router = express.Router();

router.post("/register", async (req: Request, res: Response) => {
    try {
        if(req.body.name ==null || req.body.username==null || req.body.email==null || req.body.password==null){
            return res.status(400).json({ error: "Missing Params" });
        }
        if(!req.body.email.toString().includes("@")){res.status(500).json({ error: "El email es invalido" });}
        const hashedPassword = await bcrypt.hash(req.body.password,10);
        const user = new User({
            id: crypto.randomUUID(),
            username: req.body.username,
            name: req.body.name,
            email: req.body.email,
            password: hashedPassword,
            photo: req.body.photo || "default",
        });
        await user.save();
        const token = await createJWT({ username:user.username});
        res.set({
         "Set-Cookie": `bearer=${token}; Secure; Path=/; SameSite=Strict`
        }).status(200).json({success:"OK",username:user.username});
    } catch (_err: Error | any) {
        res.status(500).json({ error: "Internal Server Error" });
    }
});

router.post("/login", async (req: Request, res: Response) => {
  try {
    if (req.body.username == null || req.body.password == null) {
      return res.status(400).json({ error: "Missing params" });
    }
    const username = req.body.username;
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(404).json({ error: "Not found" });
    }
    if (!await bcrypt.compare(req.body.password, user.password)) {
      user.intentos--;
      await user.save();
      //Prevent Dictionary Attacks
      if (user.intentos <= 0) {
        return res.status(404).json({ error: "Anti-BrutteForce Triggered" });
      }
      return res.status(404).json({ error: "Bad credentials" });
    }
    user.intentos = 3;
    await user.save();
    const token = await createJWT({ username: user.username });
    return res.set({
      "Set-Cookie": `bearer=${token}; Secure; Path=/; SameSite=Strict`
    }).status(200).json({ success: "OK", username: user.username });
  } catch (_err: Error | any) {
    return res.status(500).json({ error: "Internal Server Error" });
  }
});

export default router;

