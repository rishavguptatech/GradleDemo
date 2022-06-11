package com.pluralsight;

import com.pluralsight.http.Client;

public class Terminal {

    public static void main(String[] args) {
        Client client = new Client();

        client.getImage("");
    }
}
