package openpgp.utils;

import openpgp.exceptions.BadUserIdFormat;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;

import java.time.Instant;

/**
 * The type Naming utils.
 */
public class ConstantAndNamingUtils {

    public static final String SENDER_SECRET_KEY_RING = "./data/sender-secret-key-ring.pgp";
    public static final String SENDER_PUBLIC_KEY_RING = "./data/sender-public-key-ring.pgp";

    public static final String RECEIVER_SECRET_KEY_RING = "./data/receiver-secret-key-ring.pgp";
    public static final String RECEIVER_PUBLIC_KEY_RING = "./data/receiver-public-key-ring.pgp";

    public static final String EL_GAMAL_ALGORITHM_NAME = "ELGAMAL";
    public static final int EL_GAMAL_ALGORITHM_TAG =  PublicKeyAlgorithmTags.ELGAMAL_GENERAL;

    public static final String DSA_ALGORITHM_NAME = "DSA";
    public static final int DSA_ALGORITHM_TAG =  PublicKeyAlgorithmTags.DSA;
    /**
     * Generates public key file name by userId.
     *
     * @param userId the user id
     * @return generated file name
     */
    private static int counter = 0;
    public static String generatePublicKeyFileName(String userId){
        //return String.format("./data/export/%s-public-key-%s.asc", userId, Instant.now().getNano());
        return String.format("./data/export/%s-public-key-%s.asc", userId, counter++);
    }

    /**
     * Decodes user's Id into name and email Strings
     *
     * @param userId the user id
     * @return user 's name at [0] and user's email at [1]
     * @throws BadUserIdFormat the bad user id format
     */
    public static String[] getUserCredentialsFromId(String userId) throws BadUserIdFormat {
        String[] retVal = userId.split("__");

        if(retVal.length != 2){
            throw new BadUserIdFormat("User id " + userId + " is in incorrect format");
        }

        return retVal;
    }

    /**
     * Generate user id string.
     *
     * @param name  the name
     * @param email the email
     * @return userId
     */
    public static String generateUserId(String name, String email){
        return String.format("%s__%s", name, email);
    }


    private ConstantAndNamingUtils(){
        //
    }
}
