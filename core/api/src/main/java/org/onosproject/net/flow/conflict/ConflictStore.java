package org.onosproject.net.flow.conflict;

import org.mapdb.DB;
import org.mapdb.DBMaker;

import java.io.File;
import java.util.concurrent.ConcurrentNavigableMap;

public class ConflictStore {
    public static String dbFileName = "/home/lhf/conflict.db";
    public static DB db = DBMaker.newFileDB(new File(dbFileName))
            .closeOnJvmShutdown()
            .mmapFileEnable()
            .encryptionEnable("password")
            .make();
    public static ConcurrentNavigableMap<Integer,String> map = db.getTreeMap("conflictInfo");
    public static void storeConflict(String value){
        map.put(map.size(),value);
        db.commit();
    }

    public static String getConflict(int index){
        if(map.size()<=index){
            return null;
        }else{
            return map.get(index);
        }

    }

}
