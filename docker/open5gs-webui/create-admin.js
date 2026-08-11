const mongoose = require("mongoose");
const Account = require("./server/models/account");

const db = process.env.DB_URI || "mongodb://mongodb/open5gs";

mongoose.connect(db);

mongoose.connection.once("open", async () => {
    try {
        const existing = await Account.findOne({ username: "admin" });

        if (existing) {
            console.log("Admin already exists");
            process.exit(0);
        }

        await new Promise((resolve, reject) => {
            Account.register(
                new Account({
                    username: "admin",
                    roles: ["admin"]
                }),
                "admin",
                err => err ? reject(err) : resolve()
            );
        });

        console.log("Created admin/admin");
        process.exit(0);

    } catch (e) {
        console.error(e);
        process.exit(1);
    }
});